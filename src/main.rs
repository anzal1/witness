use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use witness::cas::Cas;
use witness::identity::{self, Delegation, Keypair};
use witness::journal::{self, Journal};
use witness::{client, merkle, mock, proxy};

#[derive(Parser)]
#[command(
    name = "witness",
    version,
    about = "A flight recorder that pays for itself: provenance-native caching proxy for model APIs.\nComposes Pact (signed agent identity + delegation chains) and AgentReplay (hash-chained traces + replay)."
)]
struct Cli {
    /// Data directory (journal, objects, cache, commitments).
    #[arg(long, global = true, default_value = "witness-data")]
    data_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the recording proxy in front of a model API.
    Serve {
        #[arg(long, default_value_t = 8787)]
        port: u16,
        /// Upstream base URL, e.g. https://api.anthropic.com
        #[arg(long, default_value = "https://api.anthropic.com")]
        upstream: String,
        /// Identity policy: open (record what's offered) or required (valid chain mandatory).
        #[arg(long, default_value = "open")]
        mode: String,
        /// Trusted root public keys (hex). Repeatable. Empty = any valid chain.
        #[arg(long)]
        trust: Vec<String>,
        /// Enable cache reuse for deterministic requests (recording always happens).
        #[arg(long)]
        cache: bool,
    },
    /// Serve strictly from the recorded run — zero upstream calls.
    Replay {
        #[arg(long, default_value_t = 8787)]
        port: u16,
    },
    /// Run a fake Anthropic-shaped upstream for demos and tests.
    Mock {
        #[arg(long, default_value_t = 9700)]
        port: u16,
        /// Simulated inference latency per call.
        #[arg(long, default_value_t = 800)]
        latency_ms: u64,
    },
    /// Generate an Ed25519 keypair (writes <out>.key and <out>.pub).
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Issue a delegation, optionally extending an existing chain.
    Delegate {
        /// Issuer key file (path to .key, or basename).
        #[arg(long)]
        issuer: PathBuf,
        /// Subject public key (hex, or path to a .pub file).
        #[arg(long)]
        subject: String,
        /// Capability, repeatable — e.g. "model:claude-*".
        #[arg(long = "cap", required = true)]
        caps: Vec<String>,
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
        /// Existing chain file to extend (issuer must be its final subject).
        #[arg(long)]
        parent: Option<PathBuf>,
        /// Output chain file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Send a signed request through the proxy (test client).
    Call {
        #[arg(long, default_value = "http://127.0.0.1:8787")]
        to: String,
        #[arg(long, default_value = "/v1/messages")]
        path: String,
        /// Prompt text (builds a minimal messages body), or use --body-file.
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        body_file: Option<PathBuf>,
        #[arg(long, default_value = "claude-sonnet-5")]
        model: String,
        /// Signing key (enables Pact headers).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Delegation chain file.
        #[arg(long)]
        chain: Option<PathBuf>,
        /// Opt this request into cache reuse (x-witness-cache: allow).
        #[arg(long)]
        cache_opt_in: bool,
    },
    /// Verify the journal's hash chain end to end.
    Verify,
    /// Print journal records (newest last).
    Log {
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
    /// Verify the chain and write a Merkle commitment over the journal.
    Commit,
    /// Produce an inclusion proof for one record against a commitment.
    Prove {
        #[arg(long)]
        seq: u64,
        /// Commitment file; defaults to the latest in commitments/.
        #[arg(long)]
        commitment: Option<PathBuf>,
    },
    /// Verify an inclusion proof file (optionally against an expected root).
    VerifyProof {
        proof: PathBuf,
        #[arg(long)]
        root: Option<String>,
    },
    /// Search every recorded request/response for a string; report which agents touched it.
    Audit {
        #[arg(long)]
        contains: String,
    },
    /// Journal and cache statistics.
    Stats,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = cli.data_dir;
    match cli.command {
        Command::Serve {
            port,
            upstream,
            mode,
            trust,
            cache,
        } => {
            let mode = match mode.as_str() {
                "open" => proxy::Mode::Open,
                "required" => proxy::Mode::Required,
                other => bail!("unknown mode '{other}' (use open|required)"),
            };
            let trust = resolve_pubkeys(trust)?;
            proxy::serve(proxy::Options {
                port,
                upstream,
                data_dir,
                mode,
                trust,
                cache,
                replay: false,
            })
            .await
        }
        Command::Replay { port } => {
            proxy::serve(proxy::Options {
                port,
                upstream: "replay://".into(),
                data_dir,
                mode: proxy::Mode::Open,
                trust: Vec::new(),
                cache: true,
                replay: true,
            })
            .await
        }
        Command::Mock { port, latency_ms } => mock::serve(port, latency_ms).await,
        Command::Keygen { out } => {
            let key = Keypair::generate()?;
            key.save(&out)?;
            println!("{}", key.public_hex());
            eprintln!(
                "wrote {}.key (secret) and {}.pub",
                out.display(),
                out.display()
            );
            Ok(())
        }
        Command::Delegate {
            issuer,
            subject,
            caps,
            ttl_secs,
            parent,
            out,
        } => {
            let issuer_key = Keypair::load(&issuer)?;
            let subject_hex = if subject.ends_with(".pub") || PathBuf::from(&subject).exists() {
                std::fs::read_to_string(&subject)
                    .with_context(|| format!("reading {subject}"))?
                    .trim()
                    .to_string()
            } else {
                subject
            };
            let mut chain: Vec<Delegation> = match &parent {
                Some(p) => serde_json::from_slice(&std::fs::read(p)?)?,
                None => Vec::new(),
            };
            if let Some(last) = chain.last() {
                if last.subject != issuer_key.public_hex() {
                    bail!("issuer key is not the final subject of the parent chain");
                }
            }
            let delegation = Delegation::issue(&issuer_key, &subject_hex, caps, ttl_secs)?;
            chain.push(delegation);
            // Fail fast if the chain we just built wouldn't verify (e.g. escalation).
            identity::verify_chain(&chain, journal::now_ms())
                .context("resulting chain does not verify")?;
            std::fs::write(&out, serde_json::to_vec_pretty(&chain)?)?;
            eprintln!("wrote chain ({} links) to {}", chain.len(), out.display());
            Ok(())
        }
        Command::Call {
            to,
            path,
            text,
            body_file,
            model,
            key,
            chain,
            cache_opt_in,
        } => {
            let body: Value = match (text, body_file) {
                (_, Some(file)) => serde_json::from_slice(&std::fs::read(file)?)?,
                (Some(prompt), None) => serde_json::json!({
                    "model": model,
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": prompt}],
                }),
                (None, None) => bail!("provide --text or --body-file"),
            };
            client::call(client::CallOptions {
                to: &to,
                path: &path,
                body,
                key: key.as_deref(),
                chain: chain.as_deref(),
                cache_opt_in,
            })
            .await
        }
        Command::Verify => {
            let records = Journal::read_all_from(&data_dir.join("journal.log"))?;
            let n = Journal::verify_chain(&records)?;
            println!("journal OK: {n} records, chain intact");
            Ok(())
        }
        Command::Log { tail } => {
            let records = Journal::read_all_from(&data_dir.join("journal.log"))?;
            let start = records.len().saturating_sub(tail);
            for r in &records[start..] {
                println!(
                    "#{:<5} {}  {:<6} {:<7} {}  agent={}  req={}  resp={}",
                    r.seq,
                    r.ts_ms,
                    r.cache,
                    r.status,
                    r.model.as_deref().unwrap_or("-"),
                    &r.agent[..r.agent.len().min(12)],
                    &r.req[..12],
                    &r.resp[..12],
                );
            }
            Ok(())
        }
        Command::Commit => {
            let records = Journal::read_all_from(&data_dir.join("journal.log"))?;
            if records.is_empty() {
                bail!("journal is empty; nothing to commit");
            }
            Journal::verify_chain(&records).context("refusing to commit a broken chain")?;
            let leaves = Journal::leaf_hashes(&records);
            let root = merkle::root(&leaves).unwrap();
            let commitment = serde_json::json!({
                "root": hex::encode(root),
                "count": records.len(),
                "first_seq": records.first().unwrap().seq,
                "last_seq": records.last().unwrap().seq,
                "ts_ms": journal::now_ms(),
            });
            let dir = data_dir.join("commitments");
            std::fs::create_dir_all(&dir)?;
            let path = dir.join(format!("{}-{}.json", journal::now_ms(), records.len()));
            std::fs::write(&path, serde_json::to_vec_pretty(&commitment)?)?;
            println!("root: {}", hex::encode(root));
            eprintln!(
                "committed {} records -> {}\n(anchor this root externally — a transparency log, a tweet, an email — to make it binding)",
                records.len(),
                path.display()
            );
            Ok(())
        }
        Command::Prove { seq, commitment } => {
            let commitment_path = match commitment {
                Some(p) => p,
                None => latest_commitment(&data_dir)?,
            };
            let commitment: Value = serde_json::from_slice(&std::fs::read(&commitment_path)?)?;
            let count = commitment["count"].as_u64().unwrap() as usize;
            let first_seq = commitment["first_seq"].as_u64().unwrap();
            let records = Journal::read_all_from(&data_dir.join("journal.log"))?;
            if records.len() < count {
                bail!("journal has fewer records than the commitment covers");
            }
            let committed = &records[..count];
            Journal::verify_chain(committed)?;
            let index = seq
                .checked_sub(first_seq)
                .filter(|i| (*i as usize) < count)
                .with_context(|| format!("seq {seq} is not covered by this commitment"))?
                as usize;
            let leaves = Journal::leaf_hashes(committed);
            let proof = merkle::prove(&leaves, index).unwrap();
            if proof.root != commitment["root"].as_str().unwrap() {
                bail!("computed root does not match the commitment — journal was modified");
            }
            let out = serde_json::json!({
                "record": committed[index],
                "proof": proof,
                "commitment": commitment,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
        Command::VerifyProof { proof, root } => {
            let bundle: Value = serde_json::from_slice(&std::fs::read(&proof)?)?;
            let inclusion: merkle::InclusionProof =
                serde_json::from_value(bundle["proof"].clone())?;
            if !merkle::verify(&inclusion) {
                bail!("inclusion proof INVALID");
            }
            if let Some(expected) = root {
                if inclusion.root != expected.trim() {
                    bail!("proof verifies, but against a DIFFERENT root than expected");
                }
            }
            // The proof's leaf must also be the hash of the embedded record.
            let record: journal::Record = serde_json::from_value(bundle["record"].clone())?;
            if record.hash != inclusion.leaf {
                bail!("embedded record does not match the proven leaf");
            }
            println!(
                "proof OK: record seq {} (agent {}) is committed under root {}",
                record.seq, record.agent, inclusion.root
            );
            Ok(())
        }
        Command::Audit { contains } => {
            let records = Journal::read_all_from(&data_dir.join("journal.log"))?;
            Journal::verify_chain(&records).context("journal chain broken — audit unreliable")?;
            let cas = Cas::open(&data_dir)?;
            let needle = contains.as_bytes();
            let mut matches = 0usize;
            for r in &records {
                for (side, hash) in [("request", &r.req), ("response", &r.resp)] {
                    if let Ok(Some(obj)) = cas.get(hash) {
                        if obj.windows(needle.len()).any(|w| w == needle) {
                            matches += 1;
                            println!(
                                "MATCH seq {} {}  agent={}  root={}  model={}",
                                r.seq,
                                side,
                                r.agent,
                                r.root.as_deref().unwrap_or("-"),
                                r.model.as_deref().unwrap_or("-")
                            );
                        }
                    }
                }
            }
            if matches == 0 {
                println!(
                    "no record among {} verified journal entries contains \"{contains}\"",
                    records.len()
                );
                if let Ok(path) = latest_commitment(&data_dir) {
                    let c: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                    println!(
                        "statement: as of committed root {} ({} records), no agent request or response contained it",
                        c["root"].as_str().unwrap_or("?"),
                        c["count"]
                    );
                }
            } else {
                println!("{matches} match(es)");
            }
            Ok(())
        }
        Command::Stats => {
            let records = Journal::read_all_from(&data_dir.join("journal.log"))?;
            let total = records.len();
            let hits = records.iter().filter(|r| r.cache == "hit").count();
            let replays = records.iter().filter(|r| r.cache == "replay").count();
            let misses = records.iter().filter(|r| r.cache == "miss").count();
            let signed = records.iter().filter(|r| r.sig.is_some()).count();
            let agents: std::collections::BTreeSet<_> =
                records.iter().map(|r| r.agent.as_str()).collect();
            println!("records:  {total}");
            println!("misses:   {misses}");
            println!(
                "hits:     {hits} ({}%)",
                (hits * 100).checked_div(total).unwrap_or(0)
            );
            println!("replays:  {replays}");
            println!("signed:   {signed}");
            println!("agents:   {}", agents.len());
            Ok(())
        }
    }
}

fn resolve_pubkeys(values: Vec<String>) -> Result<Vec<String>> {
    values
        .into_iter()
        .map(|v| {
            if v.ends_with(".pub") || PathBuf::from(&v).exists() {
                Ok(std::fs::read_to_string(&v)
                    .with_context(|| format!("reading {v}"))?
                    .trim()
                    .to_string())
            } else {
                Ok(v)
            }
        })
        .collect()
}

fn latest_commitment(data_dir: &std::path::Path) -> Result<PathBuf> {
    let dir = data_dir.join("commitments");
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .context("no commitments yet — run `witness commit` first")?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    entries.sort();
    entries
        .pop()
        .context("no commitments yet — run `witness commit` first")
}
