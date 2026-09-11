//! Verifier oracles: an external check that vouches for one recorded response.
//!
//! The cache reuses a response only when sampling says it is safe to (see
//! `proxy::reusable`). An oracle is the other way to get there: if a command
//! you chose looked at the response body and exited 0 (the test suite passed,
//! the proof checked, the schema validated) then the answer is good on its
//! own terms and its temperature stops mattering. Attesting a record writes a
//! marker keyed by the original request's cache key, which makes that exact
//! request unconditionally reusable, and appends a journal record naming the
//! command that vouched for it so an auditor can judge the oracle, not just
//! trust the verdict.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cas::Cas;
use crate::hash::request_key;
use crate::identity::Keypair;
use crate::journal::{now_ms, InvokeEntry, Journal, Record};

/// Marker directory under the data dir: one file per attested request key.
pub const ATTESTED_DIR: &str = "attested";
/// Journal `path` prefix that marks a record as an attestation.
pub const ATTEST_PREFIX: &str = "attest:";
/// Journal `upstream` value for attestations: no model was called.
pub const ATTEST_UPSTREAM: &str = "oracle";
/// Recorded `agent` when the attestation is not signed by a key.
pub const ANONYMOUS_ATTESTER: &str = "oracle";
/// The proxy is path-agnostic, but only POST carries a model request body,
/// so that is what a cache key is reconstructed with unless told otherwise.
pub const DEFAULT_METHOD: &str = "POST";

/// The oracle's stdout is evidence, not a payload; a runaway command must not
/// be able to fill the CAS with it.
const MAX_ORACLE_OUTPUT: usize = 256 * 1024;

pub struct AttestOptions<'a> {
    pub data_dir: &'a Path,
    /// Journal sequence number of the record to attest.
    pub seq: u64,
    /// Shell command; the response body arrives on its stdin.
    pub oracle: &'a str,
    /// Human label recorded in the journal path, e.g. "pytest".
    pub name: &'a str,
    /// Key that signs the target record's chain hash, if any.
    pub key: Option<&'a Path>,
    /// HTTP method to reconstruct the cache key with.
    pub method: &'a str,
}

/// What the oracle said, and what witness did about it.
#[derive(Debug)]
pub struct Attestation {
    pub verified: bool,
    pub exit_code: i32,
    pub target_seq: u64,
    pub target_hash: String,
    pub req_key: String,
    /// Sequence of the appended attestation record. `None` when refuted.
    pub seq: Option<u64>,
    /// CAS hash of the attestation evidence. `None` when refuted.
    pub evidence: Option<String>,
    pub attester: String,
}

/// The evidence object stored in the CAS and pointed at by the record's `resp`.
#[derive(Serialize)]
struct Evidence<'a> {
    kind: &'static str,
    name: &'a str,
    oracle: &'a str,
    method: &'a str,
    target_seq: u64,
    target_hash: &'a str,
    target_path: &'a str,
    /// CAS hash of the response body the oracle read.
    target_resp: &'a str,
    req_key: &'a str,
    exit_code: i32,
    stdout: String,
    truncated: bool,
    attester: &'a str,
    ts_ms: u64,
}

/// The marker the proxy reads. Its filename is the request key; the contents
/// exist so `witness attested` can explain an entry without a journal scan.
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct Marker {
    pub req_key: String,
    pub name: String,
    /// Sequence of the attestation record.
    pub seq: u64,
    pub target_seq: u64,
    pub attester: String,
    pub ts_ms: u64,
}

pub fn attested_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(ATTESTED_DIR)
}

/// Cheap existence check on the proxy's hot path: one stat, no read.
pub fn is_attested(attested_dir: &Path, req_key: &str) -> bool {
    attested_dir.join(req_key).exists()
}

/// Reconstruct the cache index key of the request a record describes.
///
/// The journal stores `req` as the CAS hash of the *raw* request bytes, while
/// the cache is keyed by `request_key(method, path, body)` over the canonical
/// body. The raw bytes round-trip out of the CAS unchanged, so re-running the
/// same key function over them reproduces the proxy's key exactly.
pub fn req_key_for(cas: &Cas, record: &Record, method: &str) -> Result<String> {
    let body = cas
        .get(&record.req)?
        .with_context(|| format!("request body {} is missing from the CAS", record.req))?;
    Ok(request_key(method, &record.path, &body))
}

/// Run the oracle with `body` on stdin. Returns its exit code and stdout.
/// A command killed by a signal reports 128 + signal, as a shell would.
pub fn run_oracle(command: &str, body: &[u8]) -> Result<(i32, Vec<u8>)> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning oracle: {command}"))?;
    {
        let mut stdin = child.stdin.take().expect("stdin is piped");
        // A command that never reads stdin (`grep -q` stops at the first
        // match) closes the pipe early; that is a verdict, not a failure.
        if let Err(e) = stdin.write_all(body) {
            if e.kind() != std::io::ErrorKind::BrokenPipe {
                return Err(e).context("writing the response body to the oracle");
            }
        }
    }
    let out = child.wait_with_output().context("waiting for the oracle")?;
    let code = out.status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            out.status.signal().map(|s| 128 + s).unwrap_or(-1)
        }
        #[cfg(not(unix))]
        {
            -1
        }
    });
    Ok((code, out.stdout))
}

/// Load record `seq`, run the oracle over its response body, and on exit 0
/// record the attestation and make the request unconditionally reusable.
pub fn attest(opts: AttestOptions) -> Result<Attestation> {
    if opts.name.contains(':') {
        bail!("oracle name must not contain ':' (it separates the journal path fields)");
    }
    let records = Journal::read_all_from(&opts.data_dir.join("journal.log"))?;
    let record = records
        .iter()
        .find(|r| r.seq == opts.seq)
        .with_context(|| format!("no journal record with seq {}", opts.seq))?
        .clone();
    if record.path.starts_with(ATTEST_PREFIX) {
        bail!(
            "seq {} is itself an attestation; attest the call it vouches for instead",
            opts.seq
        );
    }

    let cas = Cas::open(opts.data_dir)?;
    let response = cas
        .get(&record.resp)?
        .with_context(|| format!("response body {} is missing from the CAS", record.resp))?;
    let req_key = req_key_for(&cas, &record, opts.method)?;

    let (exit_code, stdout) = run_oracle(opts.oracle, &response)?;
    let truncated = stdout.len() > MAX_ORACLE_OUTPUT;
    let evidence_stdout =
        String::from_utf8_lossy(&stdout[..stdout.len().min(MAX_ORACLE_OUTPUT)]).into_owned();

    let key = match opts.key {
        Some(path) => Some(Keypair::load(path)?),
        None => None,
    };
    let attester = key
        .as_ref()
        .map(|k| k.public_hex())
        .unwrap_or_else(|| ANONYMOUS_ATTESTER.to_string());

    if exit_code != 0 {
        // A refuted attestation changes nothing: no marker, no record. The
        // journal must not carry a "verified" entry for a failed check.
        return Ok(Attestation {
            verified: false,
            exit_code,
            target_seq: record.seq,
            target_hash: record.hash,
            req_key,
            seq: None,
            evidence: None,
            attester,
        });
    }

    let evidence = Evidence {
        kind: "attestation",
        name: opts.name,
        oracle: opts.oracle,
        method: opts.method,
        target_seq: record.seq,
        target_hash: &record.hash,
        target_path: &record.path,
        target_resp: &record.resp,
        req_key: &req_key,
        exit_code,
        stdout: evidence_stdout,
        truncated,
        attester: &attester,
        ts_ms: now_ms(),
    };
    let evidence_hash = cas.put(&serde_json::to_vec(&evidence)?)?;

    // The signature covers the target record's chain hash, which commits to
    // that record and every record before it.
    let sig = key
        .as_ref()
        .map(|k| crate::identity::sign_bytes(k, record.hash.as_bytes()));

    let journal = Journal::open(opts.data_dir)?;
    let appended = journal.append_invoke(InvokeEntry {
        agent: attester.clone(),
        root: None,
        req: record.hash.clone(),
        resp: evidence_hash.clone(),
        path: format!("{ATTEST_PREFIX}{}:{}", opts.name, record.seq),
        model: record.model.clone(),
        upstream: ATTEST_UPSTREAM.into(),
        cache: "miss".into(),
        status: 200,
        sig,
    })?;

    write_marker(
        opts.data_dir,
        &Marker {
            req_key: req_key.clone(),
            name: opts.name.to_string(),
            seq: appended.seq,
            target_seq: record.seq,
            attester: attester.clone(),
            ts_ms: appended.ts_ms,
        },
    )?;

    Ok(Attestation {
        verified: true,
        exit_code,
        target_seq: record.seq,
        target_hash: record.hash,
        req_key,
        seq: Some(appended.seq),
        evidence: Some(evidence_hash),
        attester,
    })
}

/// Publish the marker atomically: the proxy only ever stats it, but a torn
/// file would still break `witness attested`.
fn write_marker(data_dir: &Path, marker: &Marker) -> Result<()> {
    let dir = attested_dir(data_dir);
    std::fs::create_dir_all(&dir).context("creating the attested dir")?;
    let path = dir.join(&marker.req_key);
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec(marker)?)?;
    if let Err(e) = std::fs::rename(&tmp, &path) {
        std::fs::remove_file(&tmp).ok();
        return Err(e).context("publishing the attestation marker");
    }
    Ok(())
}

/// Every attestation marker, oldest first.
pub fn list(data_dir: &Path) -> Result<Vec<Marker>> {
    let dir = attested_dir(data_dir);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("reading the attested dir"),
    };
    let mut markers: Vec<Marker> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.to_string_lossy().contains(".tmp.") {
            continue;
        }
        let data = std::fs::read(&path)?;
        markers.push(
            serde_json::from_slice(&data)
                .with_context(|| format!("{} is not an attestation marker", path.display()))?,
        );
    }
    markers.sort_by_key(|m| m.seq);
    Ok(markers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("witness-oracle-{tag}-{}", std::process::id()))
    }

    /// Record a call the way the proxy does: body in the CAS, journal entry
    /// pointing at both halves. Returns the proxy's own cache key for it.
    fn record_call(dir: &Path, path: &str, body: &[u8], response: &[u8]) -> String {
        let cas = Cas::open(dir).unwrap();
        let journal = Journal::open(dir).unwrap();
        journal
            .append_invoke(InvokeEntry {
                agent: "anonymous".into(),
                root: None,
                req: cas.put(body).unwrap(),
                resp: cas.put(response).unwrap(),
                path: path.into(),
                model: Some("claude-sonnet-5".into()),
                upstream: "http://127.0.0.1:9700".into(),
                cache: "miss".into(),
                status: 200,
                sig: None,
            })
            .unwrap();
        request_key("POST", path, body)
    }

    #[test]
    fn seq_maps_back_to_the_proxys_cache_key() {
        let dir = tmp_dir("mapping");
        std::fs::remove_dir_all(&dir).ok();
        // Raw bytes with incidental whitespace and unsorted keys: the cache
        // key canonicalizes both away, and the round-trip must too.
        let body = br#"{ "temperature": 1.0, "model": "claude-sonnet-5" }"#;
        let proxy_key = record_call(&dir, "/v1/messages", body, b"{}");

        let cas = Cas::open(&dir).unwrap();
        let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
        let derived = req_key_for(&cas, &records[0], "POST").unwrap();
        assert_eq!(derived, proxy_key, "seq -> req_key must reproduce the key");
        // Same logical body, different spelling: still the same key.
        assert_eq!(
            derived,
            request_key(
                "POST",
                "/v1/messages",
                br#"{"model":"claude-sonnet-5","temperature":1.0}"#
            )
        );
        // The method and path are part of the key, so a wrong method cannot
        // silently attest someone else's request.
        assert_ne!(derived, req_key_for(&cas, &records[0], "GET").unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verified_oracle_marks_the_request_reusable() {
        let dir = tmp_dir("verified");
        std::fs::remove_dir_all(&dir).ok();
        let req_key = record_call(&dir, "/v1/messages", b"{\"a\":1}", b"the proof checks out");

        let result = attest(AttestOptions {
            data_dir: &dir,
            seq: 1,
            oracle: "grep -q 'proof checks out'",
            name: "grep",
            key: None,
            method: DEFAULT_METHOD,
        })
        .unwrap();
        assert!(result.verified);
        assert_eq!(result.req_key, req_key);
        assert_eq!(result.seq, Some(2));
        assert!(is_attested(&attested_dir(&dir), &req_key));

        let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
        assert_eq!(Journal::verify_chain(&records).unwrap(), 2);
        let attestation = &records[1];
        assert_eq!(attestation.path, "attest:grep:1");
        assert_eq!(attestation.upstream, ATTEST_UPSTREAM);
        assert_eq!(attestation.agent, ANONYMOUS_ATTESTER);
        // req points at the attested record's chain hash, not a body.
        assert_eq!(attestation.req, records[0].hash);
        // resp resolves to evidence naming the exact command that vouched.
        let cas = Cas::open(&dir).unwrap();
        let evidence: serde_json::Value =
            serde_json::from_slice(&cas.get(&attestation.resp).unwrap().unwrap()).unwrap();
        assert_eq!(evidence["oracle"], "grep -q 'proof checks out'");
        assert_eq!(evidence["target_seq"], 1);
        assert_eq!(evidence["exit_code"], 0);

        let markers = list(&dir).unwrap();
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].name, "grep");
        assert_eq!(markers[0].target_seq, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuted_oracle_changes_nothing() {
        let dir = tmp_dir("refuted");
        std::fs::remove_dir_all(&dir).ok();
        let req_key = record_call(&dir, "/v1/messages", b"{\"a\":1}", b"nonsense");

        let result = attest(AttestOptions {
            data_dir: &dir,
            seq: 1,
            oracle: "grep -q 'proof checks out'",
            name: "grep",
            key: None,
            method: DEFAULT_METHOD,
        })
        .unwrap();
        assert!(!result.verified);
        assert_eq!(result.exit_code, 1);
        assert_eq!(result.seq, None);
        assert_eq!(result.evidence, None);
        // No marker, so the request stays as reusable as its sampling says.
        assert!(!is_attested(&attested_dir(&dir), &req_key));
        assert!(list(&dir).unwrap().is_empty());
        // And nothing was journaled: a refutation is not a verification.
        let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
        assert_eq!(records.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oracle_exit_code_is_reported_verbatim() {
        let (code, out) = run_oracle("cat; exit 7", b"body").unwrap();
        assert_eq!(code, 7);
        assert_eq!(out, b"body");
    }

    #[test]
    fn attesting_an_attestation_is_refused() {
        let dir = tmp_dir("nested");
        std::fs::remove_dir_all(&dir).ok();
        record_call(&dir, "/v1/messages", b"{\"a\":1}", b"ok");
        attest(AttestOptions {
            data_dir: &dir,
            seq: 1,
            oracle: "true",
            name: "always",
            key: None,
            method: DEFAULT_METHOD,
        })
        .unwrap();
        let err = attest(AttestOptions {
            data_dir: &dir,
            seq: 2,
            oracle: "true",
            name: "always",
            key: None,
            method: DEFAULT_METHOD,
        })
        .unwrap_err();
        assert!(err.to_string().contains("itself an attestation"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signed_attestation_verifies_against_the_target_hash() {
        let dir = tmp_dir("signed");
        std::fs::remove_dir_all(&dir).ok();
        record_call(&dir, "/v1/messages", b"{\"a\":1}", b"ok");
        let key = Keypair::generate().unwrap();
        let key_path = dir.join("attester");
        key.save(&key_path).unwrap();

        let result = attest(AttestOptions {
            data_dir: &dir,
            seq: 1,
            oracle: "true",
            name: "always",
            key: Some(&key_path),
            method: DEFAULT_METHOD,
        })
        .unwrap();
        assert!(result.verified);
        assert_eq!(result.attester, key.public_hex());

        let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
        let sig = records[1].sig.as_ref().expect("signed attestation");
        crate::identity::verify_bytes(&key.public_hex(), sig, records[0].hash.as_bytes()).unwrap();
        // The signature is over the target's hash, not the attestation's.
        assert!(
            crate::identity::verify_bytes(&key.public_hex(), sig, records[1].hash.as_bytes())
                .is_err()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The marker is what the proxy consults, so a stray file in the dir must
    /// not be mistaken for one and a missing dir must simply mean "none".
    #[test]
    fn missing_attested_dir_is_not_an_error() {
        let dir = tmp_dir("empty");
        std::fs::remove_dir_all(&dir).ok();
        assert!(list(&dir).unwrap().is_empty());
        assert!(!is_attested(&attested_dir(&dir), &"ab".repeat(32)));
    }
}
