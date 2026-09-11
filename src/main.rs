use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use witness::cas::Cas;
use witness::identity::{self, Delegation, Keypair};
use witness::journal::{self, Journal};
use witness::{agent_record, anchor, client, mcp, merkle, mock, oracle, proxy};

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
        /// Also project each recorded call onto an OpenTelemetry GenAI span,
        /// posted to this OTLP/HTTP collector (e.g. http://127.0.0.1:4318).
        #[arg(long)]
        otlp_endpoint: Option<String>,
        /// Sibling witness instance to ask on a local cache miss, before the
        /// upstream. Repeatable, tried in order, 300ms budget each.
        #[arg(long = "peer")]
        peers: Vec<String>,
        /// Shared secret for the peer cache route: required on inbound peer
        /// reads and sent on outbound ones. Unset leaves the route open.
        #[arg(long)]
        peer_token: Option<String>,
    },
    /// Serve strictly from the recorded run — zero upstream calls.
    Replay {
        #[arg(long, default_value_t = 8787)]
        port: u16,
        /// OTLP/HTTP collector for GenAI spans, as in `serve`.
        #[arg(long)]
        otlp_endpoint: Option<String>,
    },
    /// Wrap a stdio MCP server, recording its tool calls into the same journal.
    Mcp {
        /// Journal identity recorded for this session's tool calls.
        #[arg(long, default_value = mcp::DEFAULT_AGENT)]
        agent: String,
        /// The MCP server command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
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
    /// Print Pact headers for a request body, for use with curl or load tests.
    /// Signatures stay valid for the proxy's clock-skew window (5 minutes).
    Sign {
        #[arg(long, default_value = "/v1/messages")]
        path: String,
        /// Signing key.
        #[arg(long)]
        key: PathBuf,
        /// Delegation chain file.
        #[arg(long)]
        chain: Option<PathBuf>,
        /// Body file to sign; defaults to reading stdin.
        #[arg(long)]
        body_file: Option<PathBuf>,
        /// Emit as curl -H arguments instead of plain "Name: value" lines.
        #[arg(long)]
        curl: bool,
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
    /// Run an external verifier over a recorded response. On exit 0 the
    /// attestation is journaled and that request becomes reusable regardless
    /// of the sampling parameters it was made with.
    Attest {
        /// Journal sequence number of the record to verify.
        #[arg(long)]
        seq: u64,
        /// Shell command; the recorded response body arrives on its stdin.
        /// Exit 0 verifies, any other status refutes.
        #[arg(long)]
        oracle: String,
        /// Label for this oracle, recorded in the journal, e.g. "pytest".
        #[arg(long, default_value = "oracle")]
        name: String,
        /// Key that signs the attested record's chain hash.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Method the original request used, for reconstructing its cache key.
        #[arg(long, default_value = oracle::DEFAULT_METHOD)]
        method: String,
    },
    /// List the requests a verifier oracle has made unconditionally reusable.
    Attested,
    /// Verify the journal's hash chain end to end.
    Verify,
    /// Print journal records (newest last).
    Log {
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
    /// Verify the chain and write a Merkle commitment over the journal.
    Commit,
    /// Publish a commitment to the Sigstore Rekor transparency log.
    Anchor {
        /// Ed25519 key that signs the log entry.
        #[arg(long)]
        key: PathBuf,
        /// Commitment file; defaults to the latest in commitments/.
        #[arg(long)]
        commitment: Option<PathBuf>,
        /// Transparency log to publish to.
        #[arg(long, default_value = anchor::REKOR_URL)]
        rekor_url: String,
        /// Print the exact entry that would be posted, and post nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Check a commitment against the Rekor entry that anchors it.
    AnchorVerify {
        /// Commitment file; defaults to the latest in commitments/.
        #[arg(long)]
        commitment: Option<PathBuf>,
        /// Override the log recorded in the anchor receipt.
        #[arg(long)]
        rekor_url: Option<String>,
    },
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
    /// Export the journal as an IETF agent-record dossier
    /// (draft-maintainer-1f916-agent-record-01).
    ExportRecord {
        /// Directory to write the dossier into (created if absent).
        #[arg(long)]
        out: PathBuf,
        /// Restrict the export to one agent: hex public key, or "anonymous".
        #[arg(long)]
        agent: Option<String>,
        /// Key that signs the checkpoint and the dossier (the registry role).
        /// Defaults to <data-dir>/registry, generated on first use.
        #[arg(long = "sign-key")]
        sign_key: Option<PathBuf>,
    },
    /// Offline-verify an agent-record dossier directory.
    VerifyRecord {
        dir: PathBuf,
        /// Registry public key (hex, or a .pub file) obtained out of band.
        /// Without it the strongest available verdict is "unanchored".
        #[arg(long)]
        registry_key: Option<String>,
    },
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
            otlp_endpoint,
            peers,
            peer_token,
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
                otlp_endpoint,
                peers,
                peer_token,
            })
            .await
        }
        Command::Replay {
            port,
            otlp_endpoint,
        } => {
            proxy::serve(proxy::Options {
                port,
                upstream: "replay://".into(),
                data_dir,
                mode: proxy::Mode::Open,
                trust: Vec::new(),
                cache: true,
                replay: true,
                otlp_endpoint,
                // Replay is offline by definition: it ignores the fleet.
                peers: Vec::new(),
                peer_token: None,
            })
            .await
        }
        Command::Mcp { agent, command } => {
            // Exit with the wrapped server's code: the MCP client should see
            // the process it thinks it launched, not the wrapper.
            let code = mcp::run(mcp::Options {
                data_dir,
                agent,
                command,
            })
            .await?;
            std::process::exit(code);
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
        Command::Sign {
            path,
            key,
            chain,
            body_file,
            curl,
        } => {
            let key = Keypair::load(&key)?;
            let body = match body_file {
                Some(f) => std::fs::read(&f).with_context(|| format!("reading {}", f.display()))?,
                None => {
                    use std::io::Read;
                    let mut buf = Vec::new();
                    std::io::stdin().read_to_end(&mut buf)?;
                    buf
                }
            };
            let ts = journal::now_ms();
            let sig = witness::identity::sign_request(&key, "POST", &path, ts, &body);
            let mut headers = vec![
                (witness::identity::HDR_IDENTITY, key.public_hex()),
                (witness::identity::HDR_TIMESTAMP, ts.to_string()),
                (witness::identity::HDR_SIGNATURE, sig),
            ];
            if let Some(chain_path) = chain {
                let chain: Vec<Delegation> = serde_json::from_slice(&std::fs::read(&chain_path)?)?;
                headers.push((
                    witness::identity::HDR_DELEGATION,
                    witness::identity::chain_to_b64(&chain)?,
                ));
            }
            for (name, value) in headers {
                if curl {
                    println!("-H '{name}: {value}'");
                } else {
                    println!("{name}: {value}");
                }
            }
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
        Command::Attest {
            seq,
            oracle: command,
            name,
            key,
            method,
        } => {
            let result = oracle::attest(oracle::AttestOptions {
                data_dir: &data_dir,
                seq,
                oracle: &command,
                name: &name,
                key: key.as_deref(),
                method: &method,
            })?;
            if !result.verified {
                // Nothing was written. Say so on stderr and exit with the
                // oracle's own status, so a script can branch on it.
                eprintln!(
                    "REFUTED  seq {} by {name}: `{command}` exited {}\nnothing journaled, nothing attested",
                    result.target_seq, result.exit_code
                );
                std::process::exit(if result.exit_code == 0 {
                    1
                } else {
                    result.exit_code
                });
            }
            println!(
                "VERIFIED seq {} by {name}  req_key={}",
                result.target_seq, result.req_key
            );
            eprintln!(
                "attestation recorded as seq {} (attester {}, evidence {})",
                result.seq.unwrap(),
                result.attester,
                result.evidence.as_deref().unwrap_or("-")
            );
            eprintln!("this request is now reusable from cache whatever its temperature");
            Ok(())
        }
        Command::Attested => {
            let markers = oracle::list(&data_dir)?;
            if markers.is_empty() {
                println!("no attestations yet: run `witness attest --seq <N> --oracle '<cmd>'`");
                return Ok(());
            }
            for m in &markers {
                println!(
                    "#{:<5} {:<16} target={:<5} req_key={}  attester={}",
                    m.seq,
                    m.name,
                    m.target_seq,
                    m.req_key,
                    &m.attester[..m.attester.len().min(12)],
                );
            }
            Ok(())
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
                "committed {} records -> {}\nanchor it to make it binding:  witness anchor --key <keyfile>",
                records.len(),
                path.display()
            );
            Ok(())
        }
        Command::Anchor {
            key,
            commitment,
            rekor_url,
            dry_run,
        } => {
            let commitment_path = match commitment {
                Some(p) => p,
                None => latest_commitment(&data_dir)?,
            };
            anchor::anchor(anchor::AnchorOptions {
                commitment: &commitment_path,
                key: &key,
                rekor_url: &rekor_url,
                dry_run,
            })
            .await
        }
        Command::AnchorVerify {
            commitment,
            rekor_url,
        } => {
            let commitment_path = match commitment {
                Some(p) => p,
                None => latest_commitment(&data_dir)?,
            };
            anchor::verify(&commitment_path, rekor_url.as_deref()).await
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
            let peers = records.iter().filter(|r| r.cache == "peer").count();
            let signed = records.iter().filter(|r| r.sig.is_some()).count();
            let agents: std::collections::BTreeSet<_> =
                records.iter().map(|r| r.agent.as_str()).collect();
            println!("records:  {total}");
            println!("misses:   {misses}");
            println!(
                "hits:     {hits} ({}%)",
                (hits * 100).checked_div(total).unwrap_or(0)
            );
            println!("peers:    {peers}");
            println!("replays:  {replays}");
            println!("signed:   {signed}");
            println!("agents:   {}", agents.len());
            Ok(())
        }
        Command::ExportRecord {
            out,
            agent,
            sign_key,
        } => {
            let records = Journal::read_all_from(&data_dir.join("journal.log"))?;
            Journal::verify_chain(&records).context("refusing to export a broken chain")?;
            let signer = load_or_create_registry_key(&data_dir, sign_key.as_deref())?;
            let summary = agent_record::export(agent_record::ExportOptions {
                records: &records,
                agent: agent.as_deref(),
                signer: &signer,
                out_dir: &out,
            })?;
            println!("log:       {}", summary.log);
            println!("events:    {}", summary.events);
            println!("tree_size: {}", summary.tree_size);
            println!("root:      {}", summary.root_sha256);
            for file in &summary.files {
                eprintln!("wrote {}", file.display());
            }
            eprintln!(
                "conforms to {} (see README: parts of the event schema are provisional)",
                agent_record::SPEC
            );
            eprintln!(
                "publish the registry key {} out of band — a key read from the dossier proves only internal consistency",
                signer.public_hex()
            );
            Ok(())
        }
        Command::VerifyRecord { dir, registry_key } => {
            let pin = match registry_key {
                Some(v) => Some(resolve_pubkeys(vec![v])?.remove(0)),
                None => None,
            };
            let report = agent_record::verify(&dir, pin.as_deref())?;
            println!("verdict:   {}", report.verdict.as_str());
            println!("log:       {}", report.log);
            println!("subject:   {}", report.subject);
            println!("events:    {}", report.events);
            println!("tree_size: {}", report.tree_size);
            println!("root:      {}", report.root_sha256);
            println!("signer:    {}", report.registry_key);
            if report.unsigned_bindings > 0 {
                println!(
                    "note:      {} key binding(s) carry no signature — the key was observed, not attested",
                    report.unsigned_bindings
                );
            }
            if report.verdict == agent_record::Verdict::Unanchored {
                eprintln!(
                    "unanchored: every key came from the dossier itself. Re-run with --registry-key <hex> obtained out of band."
                );
            }
            Ok(())
        }
    }
}

/// The registry-role signing key. An explicit `--sign-key` wins; otherwise
/// `<data-dir>/registry.key`, generated on first use so an export never
/// silently produces an unsigned dossier.
fn load_or_create_registry_key(
    data_dir: &std::path::Path,
    sign_key: Option<&std::path::Path>,
) -> Result<Keypair> {
    if let Some(path) = sign_key {
        return Keypair::load(path);
    }
    let default = data_dir.join("registry");
    if default.with_extension("key").exists() {
        return Keypair::load(&default);
    }
    let key = Keypair::generate()?;
    key.save(&default)?;
    eprintln!(
        "generated registry key {} -> {}.key",
        key.public_hex(),
        default.display()
    );
    Ok(key)
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
        // Anchor receipts live beside their commitments; they are not one.
        .filter(|p| !p.to_string_lossy().ends_with(".anchor.json"))
        .collect();
    entries.sort();
    entries
        .pop()
        .context("no commitments yet — run `witness commit` first")
}
