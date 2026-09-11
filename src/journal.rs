//! Append-only, hash-chained journal (JSONL). Each record's `hash` covers the
//! previous record's hash plus the record's own canonical content, so any
//! tampering — edit, deletion, reordering — breaks the chain from that point.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::hash::{canonical_json, ZERO_HASH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub seq: u64,
    pub ts_ms: u64,
    pub prev: String,
    /// "invoke" for proxied calls; other kinds may be added (e.g. "note").
    pub kind: String,
    /// Pact identity (hex pubkey) of the calling agent, or "anonymous".
    pub agent: String,
    /// Hex pubkey of the root (human) key anchoring the delegation chain, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// CAS hash of the canonical request.
    pub req: String,
    /// CAS hash of the response body.
    pub resp: String,
    pub path: String,
    pub model: Option<String>,
    pub upstream: String,
    /// "hit" | "miss" | "replay"
    pub cache: String,
    pub status: u16,
    /// Agent's request signature (hex), if the request was signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// Chain hash — blake3(prev_hash_bytes || canonical(record without hash)).
    pub hash: String,
}

impl Record {
    fn compute_hash(&self) -> String {
        let mut clone = self.clone();
        clone.hash = String::new();
        let value = serde_json::to_value(&clone).expect("record serializes");
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.prev.as_bytes());
        hasher.update(&canonical_json(&value));
        hasher.finalize().to_hex().to_string()
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Everything needed to append an invoke record; seq/prev/hash are filled in.
pub struct InvokeEntry {
    pub agent: String,
    pub root: Option<String>,
    pub req: String,
    pub resp: String,
    pub path: String,
    pub model: Option<String>,
    pub upstream: String,
    pub cache: String,
    pub status: u16,
    pub sig: Option<String>,
}

struct Inner {
    file: File,
    next_seq: u64,
    prev_hash: String,
}

pub struct Journal {
    path: PathBuf,
    inner: Mutex<Inner>,
}

impl Journal {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("journal.log");
        std::fs::create_dir_all(data_dir)?;
        // Recover chain tip by scanning existing records.
        let (next_seq, prev_hash) = match Self::read_all_from(&path) {
            Ok(records) => match records.last() {
                Some(last) => (last.seq + 1, last.hash.clone()),
                None => (1, ZERO_HASH.to_string()),
            },
            Err(_) if !path.exists() => (1, ZERO_HASH.to_string()),
            Err(e) => return Err(e).context("reading existing journal"),
        };
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            inner: Mutex::new(Inner {
                file,
                next_seq,
                prev_hash,
            }),
        })
    }

    pub fn append_invoke(&self, e: InvokeEntry) -> Result<Record> {
        let mut inner = self.inner.lock().unwrap();
        let mut record = Record {
            seq: inner.next_seq,
            ts_ms: now_ms(),
            prev: inner.prev_hash.clone(),
            kind: "invoke".into(),
            agent: e.agent,
            root: e.root,
            req: e.req,
            resp: e.resp,
            path: e.path,
            model: e.model,
            upstream: e.upstream,
            cache: e.cache,
            status: e.status,
            sig: e.sig,
            hash: String::new(),
        };
        record.hash = record.compute_hash();
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        inner.file.write_all(&line)?;
        inner.file.flush()?;
        inner.next_seq += 1;
        inner.prev_hash = record.hash.clone();
        Ok(record)
    }

    /// Sequence number of the last appended record, i.e. the journal's
    /// length, without re-reading the file.
    pub fn len(&self) -> u64 {
        self.inner.lock().unwrap().next_seq - 1
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn read_all(&self) -> Result<Vec<Record>> {
        Self::read_all_from(&self.path)
    }

    pub fn read_all_from(path: &Path) -> Result<Vec<Record>> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let reader = BufReader::new(File::open(path)?);
        let mut records = Vec::new();
        for (i, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: Record = serde_json::from_str(&line)
                .with_context(|| format!("journal line {} is not a valid record", i + 1))?;
            records.push(record);
        }
        Ok(records)
    }

    /// Verify the full hash chain. Returns the number of verified records.
    pub fn verify_chain(records: &[Record]) -> Result<usize> {
        let mut prev = ZERO_HASH.to_string();
        let first_seq = records.first().map(|r| r.seq).unwrap_or(1);
        for (offset, record) in records.iter().enumerate() {
            let expected_seq = first_seq + offset as u64;
            if record.seq != expected_seq {
                anyhow::bail!(
                    "sequence gap at seq {} (expected {})",
                    record.seq,
                    expected_seq
                );
            }
            if record.prev != prev {
                anyhow::bail!("chain break at seq {}: prev hash mismatch", record.seq);
            }
            let computed = record.compute_hash();
            if computed != record.hash {
                anyhow::bail!("tampered record at seq {}: hash mismatch", record.seq);
            }
            prev = record.hash.clone();
        }
        Ok(records.len())
    }

    pub fn leaf_hashes(records: &[Record]) -> Vec<[u8; 32]> {
        records
            .iter()
            .map(|r| {
                let mut leaf = [0u8; 32];
                hex::decode_to_slice(&r.hash, &mut leaf).expect("record hash is 32-byte hex");
                leaf
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("witness-journal-{tag}-{}", std::process::id()))
    }

    fn entry(n: u8) -> InvokeEntry {
        InvokeEntry {
            agent: "anonymous".into(),
            root: None,
            req: format!("{:064x}", n),
            resp: format!("{:064x}", n as u32 + 1000),
            path: "/v1/messages".into(),
            model: Some("claude-sonnet-5".into()),
            upstream: "mock".into(),
            cache: "miss".into(),
            status: 200,
            sig: None,
        }
    }

    #[test]
    fn chain_appends_and_verifies() {
        let dir = tmp_dir("basic");
        std::fs::remove_dir_all(&dir).ok();
        let journal = Journal::open(&dir).unwrap();
        journal.append_invoke(entry(1)).unwrap();
        journal.append_invoke(entry(2)).unwrap();
        let records = journal.read_all().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(Journal::verify_chain(&records).unwrap(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampering_is_detected() {
        let dir = tmp_dir("tamper");
        std::fs::remove_dir_all(&dir).ok();
        let journal = Journal::open(&dir).unwrap();
        journal.append_invoke(entry(1)).unwrap();
        let mut records = journal.read_all().unwrap();
        records[0].model = Some("gpt-6-astra".into());
        assert!(Journal::verify_chain(&records).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reopen_continues_chain() {
        let dir = tmp_dir("reopen");
        std::fs::remove_dir_all(&dir).ok();
        {
            let journal = Journal::open(&dir).unwrap();
            journal.append_invoke(entry(1)).unwrap();
        }
        let journal = Journal::open(&dir).unwrap();
        journal.append_invoke(entry(2)).unwrap();
        let records = journal.read_all().unwrap();
        assert_eq!(records[1].seq, 2);
        assert_eq!(Journal::verify_chain(&records).unwrap(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Journals outlive the binary that wrote them, so a record written before
    /// the tool boundary existed must still parse and still hash to the value
    /// stored in it. These two lines are verbatim output from the model-proxy
    /// path, one with the optional identity fields and one without. Any change
    /// to `Record` that alters the serialized form breaks this test, which is
    /// the point: new fields must be additive and skipped when absent.
    #[test]
    fn records_written_before_the_tool_boundary_still_verify() {
        const WITH_IDENTITY: &str = r#"{"seq":1,"ts_ms":1789112274191,"prev":"0000000000000000000000000000000000000000000000000000000000000000","kind":"invoke","agent":"b1946ac92492d2347c6235b4d2611184","root":"9f86d081884c7d659a2feaa0c55ad015","req":"0000000000000000000000000000000000000000000000000000000000000010","resp":"0000000000000000000000000000000000000000000000000000000000000011","path":"/v1/messages","model":"claude-sonnet-5","upstream":"http://127.0.0.1:9700","cache":"miss","status":200,"sig":"deadbeef","hash":"cae4937997cf7ce514f31a050e756ca6ddcdc8c858ecc8076d86478915922dcd"}"#;
        const ANONYMOUS: &str = r#"{"seq":1,"ts_ms":1789112285686,"prev":"0000000000000000000000000000000000000000000000000000000000000000","kind":"invoke","agent":"b1946ac92492d2347c6235b4d2611184","req":"0000000000000000000000000000000000000000000000000000000000000010","resp":"0000000000000000000000000000000000000000000000000000000000000011","path":"/v1/messages","model":"claude-sonnet-5","upstream":"http://127.0.0.1:9700","cache":"miss","status":200,"hash":"86c5b4bc12e270150c301a267c54a7289390f06b65c7e31683255d4226e93511"}"#;

        for line in [WITH_IDENTITY, ANONYMOUS] {
            let record: Record = serde_json::from_str(line).expect("old record parses");
            assert_eq!(record.kind, "invoke");
            assert_eq!(record.model.as_deref(), Some("claude-sonnet-5"));
            assert_eq!(
                Journal::verify_chain(std::slice::from_ref(&record)).unwrap(),
                1,
                "an old record must still hash to the value it carries"
            );
            // Round-tripping must be byte-identical, or a re-read journal
            // would no longer match the commitments taken over it.
            assert_eq!(serde_json::to_string(&record).unwrap(), line);
        }

        // The anonymous line omits `root` and `sig` entirely; they must come
        // back as None rather than failing the parse.
        let anon: Record = serde_json::from_str(ANONYMOUS).unwrap();
        assert_eq!(anon.root, None);
        assert_eq!(anon.sig, None);
    }
}
