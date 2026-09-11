//! Append-only, hash-chained journal (JSONL). Each record's `hash` covers the
//! previous record's hash plus the record's own canonical content, so any
//! tampering — edit, deletion, reordering — breaks the chain from that point.
//!
//! Writes go through a single writer thread fed by a bounded channel. An
//! append submits its entry, the writer drains everything already queued,
//! hashes the batch in submission order, and puts the whole batch on disk with
//! one `write_all` and one `flush`; only then does each caller get its record
//! back. The chain stays exactly as sequential as it was when every append
//! held a mutex over its own write, but N concurrent appends now cost one pair
//! of syscalls instead of N.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
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

/// Records fused into a single write. A couple of hundred is already enough to
/// amortise the syscall to nothing; a larger cap only lengthens the wait for
/// whoever submitted first in the batch.
const MAX_BATCH: usize = 256;

/// Submissions allowed to queue ahead of the writer. Deep enough that the
/// writer always finds a full batch under load, shallow enough that a stalled
/// disk pushes back on callers instead of growing a queue without bound.
const QUEUE_DEPTH: usize = 1024;

/// One append in flight: the entry, and the one-shot the caller is blocked on.
struct Job {
    entry: InvokeEntry,
    reply: SyncSender<Result<Record>>,
}

/// The only thing that ever writes to `journal.log`. Owns the chain tip, so
/// seq and prev are assigned in submission order by construction.
struct Writer {
    path: PathBuf,
    file: File,
    next_seq: u64,
    prev_hash: String,
    committed: Arc<AtomicU64>,
    /// Bytes this writer believes the journal holds. A mismatch against the
    /// file's real size means another process appended, so the cached tip is
    /// stale; see `commit`.
    written_len: u64,
    /// Set when a write fails partway. The file then ends at an unknown
    /// offset, so appending after it would corrupt the middle of the chain
    /// rather than its tail. Every later append fails loudly instead.
    poisoned: Option<String>,
    buf: Vec<u8>,
}

impl Writer {
    fn run(mut self, rx: Receiver<Job>) {
        let mut batch: Vec<Job> = Vec::with_capacity(MAX_BATCH);
        while let Ok(first) = rx.recv() {
            batch.push(first);
            // Whatever else arrived while the last batch was on its way to
            // disk rides along in this one.
            while batch.len() < MAX_BATCH {
                match rx.try_recv() {
                    Ok(job) => batch.push(job),
                    Err(_) => break,
                }
            }
            self.commit(&mut batch);
        }
    }

    /// Pick up a tip another process moved. `witness attest` and `witness mcp`
    /// both open their own handle on a journal a proxy may be serving from, so
    /// a cached tip can go stale between batches. One fstat notices it, and
    /// only a mismatch pays for the re-read. Because it guards the batch and
    /// not the record, a full batch of 256 amortises the check 256 ways.
    ///
    /// This closes the stale-tip case, not a true simultaneous-write race: the
    /// journal is still meant to have one hot writer per data dir.
    fn resync(&mut self) -> Result<()> {
        let on_disk = self.file.metadata().map(|m| m.len()).unwrap_or(0);
        if on_disk == self.written_len {
            return Ok(());
        }
        let (next_seq, prev_hash) = Journal::recover_tip(&self.path)?;
        self.next_seq = next_seq;
        self.prev_hash = prev_hash;
        // Re-stat rather than trusting `on_disk`: recovering the tip may have
        // trimmed a partial record the other writer left behind.
        self.written_len = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        self.committed.store(next_seq - 1, Ordering::Release);
        Ok(())
    }

    /// One group commit: hash every entry in submission order into a single
    /// buffer, then one `write_all` and one `flush`. The in-memory chain tip
    /// moves only once both have succeeded, so a failed batch leaves the
    /// journal exactly where it was.
    fn commit(&mut self, batch: &mut Vec<Job>) {
        if let Some(reason) = self.poisoned.clone() {
            for job in batch.drain(..) {
                let _ = job.reply.send(Err(anyhow!("{reason}")));
            }
            return;
        }
        if let Err(e) = self.resync() {
            // The tip was not moved and nothing was written, so a later batch
            // can still succeed once whatever damaged the file is gone. Fail
            // this one rather than chain from a tip we no longer trust.
            for job in batch.drain(..) {
                let _ = job.reply.send(Err(anyhow!("{e:#}")));
            }
            return;
        }

        self.buf.clear();
        let mut waiting = Vec::with_capacity(batch.len());
        let mut seq = self.next_seq;
        let mut prev = self.prev_hash.clone();
        for job in batch.drain(..) {
            let e = job.entry;
            let mut record = Record {
                seq,
                ts_ms: now_ms(),
                prev,
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
            serde_json::to_writer(&mut self.buf, &record).expect("record serializes");
            self.buf.push(b'\n');
            seq += 1;
            prev = record.hash.clone();
            waiting.push((record, job.reply));
        }

        match self
            .file
            .write_all(&self.buf)
            .and_then(|()| self.file.flush())
        {
            Ok(()) => {
                self.next_seq = seq;
                self.prev_hash = prev;
                self.written_len += self.buf.len() as u64;
                self.committed.store(seq - 1, Ordering::Release);
                for (record, reply) in waiting {
                    let _ = reply.send(Ok(record));
                }
            }
            Err(e) => {
                let reason = format!(
                    "journal write failed ({e}); {} is read-only for the rest of this process",
                    self.path.display()
                );
                eprintln!("witness: {reason}");
                self.poisoned = Some(reason.clone());
                for (_, reply) in waiting {
                    let _ = reply.send(Err(anyhow!("{reason}")));
                }
            }
        }
    }
}

pub struct Journal {
    path: PathBuf,
    /// `None` only while dropping, where closing the channel is what tells the
    /// writer thread to finish.
    tx: Option<SyncSender<Job>>,
    writer: Option<JoinHandle<()>>,
    committed: Arc<AtomicU64>,
}

impl Journal {
    pub fn open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join("journal.log");
        let (next_seq, prev_hash) = Self::recover_tip(&path)?;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let committed = Arc::new(AtomicU64::new(next_seq - 1));
        let writer = Writer {
            path: path.clone(),
            file,
            next_seq,
            prev_hash,
            committed: committed.clone(),
            written_len: std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
            poisoned: None,
            buf: Vec::with_capacity(64 * 1024),
        };
        let (tx, rx) = sync_channel(QUEUE_DEPTH);
        let handle = std::thread::Builder::new()
            .name("witness-journal".into())
            .spawn(move || writer.run(rx))
            .context("spawning the journal writer")?;
        Ok(Self {
            path,
            tx: Some(tx),
            writer: Some(handle),
            committed,
        })
    }

    /// Chain tip of an existing journal: the seq to write next and the hash to
    /// chain from.
    fn recover_tip(path: &Path) -> Result<(u64, String)> {
        if !path.exists() {
            return Ok((1, ZERO_HASH.to_string()));
        }
        let records = match Self::read_all_from(path) {
            Ok(records) => records,
            Err(e) => match Self::truncate_torn_tail(path) {
                // A batch reaches the kernel as one buffered write, so the
                // only damage a crash can do is cut the file mid-line. Heal
                // exactly that much. A line that is complete and still
                // unparsable, anywhere in the file, is corruption rather than
                // a torn write, and stays fatal.
                Ok(true) => Self::read_all_from(path).context("reading existing journal")?,
                Ok(false) => return Err(e).context("reading existing journal"),
                Err(trim) => {
                    eprintln!("witness: could not trim the journal's partial tail: {trim:#}");
                    return Err(e).context("reading existing journal");
                }
            },
        };
        Ok(match records.last() {
            Some(last) => (last.seq + 1, last.hash.clone()),
            None => (1, ZERO_HASH.to_string()),
        })
    }

    /// Drop a trailing fragment left by a crash mid-append. Returns whether
    /// anything was removed: a file already ending in a newline has no torn
    /// tail, whatever else may be wrong with it.
    fn truncate_torn_tail(path: &Path) -> Result<bool> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let len = file.metadata()?.len();
        if len == 0 {
            return Ok(false);
        }
        // Walk backwards to the last newline rather than reading a journal
        // that may be gigabytes into memory.
        let mut window = [0u8; 8192];
        let mut pos = len;
        let mut keep = 0;
        while pos > 0 {
            let take = std::cmp::min(pos, window.len() as u64);
            pos -= take;
            file.seek(SeekFrom::Start(pos))?;
            let slice = &mut window[..take as usize];
            file.read_exact(slice)?;
            if let Some(i) = slice.iter().rposition(|b| *b == b'\n') {
                keep = pos + i as u64 + 1;
                break;
            }
        }
        if keep == len {
            return Ok(false);
        }
        eprintln!(
            "witness: {} ends in a partial record; dropping its last {} bytes. \
             A crash during an append leaves exactly this, and the chain before it is intact.",
            path.display(),
            len - keep
        );
        file.set_len(keep)?;
        file.sync_all()?;
        Ok(true)
    }

    /// Submit an entry and block until the batch it landed in is on disk.
    /// Blocking is the contract: the record is durable, and its seq is final,
    /// before this returns.
    pub fn append_invoke(&self, e: InvokeEntry) -> Result<Record> {
        let (reply, done) = sync_channel(1);
        let tx = self
            .tx
            .as_ref()
            .context("journal writer has already shut down")?;
        tx.send(Job { entry: e, reply })
            .map_err(|_| anyhow!("journal writer stopped"))?;
        done.recv()
            .map_err(|_| anyhow!("journal writer dropped the append"))?
    }

    /// Sequence number of the last committed record, i.e. the journal's
    /// length, without re-reading the file.
    pub fn len(&self) -> u64 {
        self.committed.load(Ordering::Acquire)
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

impl Drop for Journal {
    fn drop(&mut self) {
        // Every append has already been flushed by the time it returned, so
        // there is nothing left to write. Closing the channel and joining is
        // only so the file handle is released before `drop` returns.
        self.tx.take();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
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

    /// The group-commit writer's whole job. Sixty-four threads pile appends in
    /// as fast as they can, which is the only way to get batches larger than
    /// one, and the chain must come out exactly as if they had queued up one
    /// at a time: contiguous seqs, an unbroken chain, and the record each
    /// caller was handed identical to the one that landed on disk.
    #[test]
    fn concurrent_appends_form_one_unbroken_chain() {
        const THREADS: usize = 64;
        const PER_THREAD: usize = 200;
        let dir = tmp_dir("storm");
        std::fs::remove_dir_all(&dir).ok();
        let journal = Journal::open(&dir).unwrap();

        let mut returned: Vec<Record> = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..THREADS)
                .map(|t| {
                    let journal = &journal;
                    scope.spawn(move || {
                        (0..PER_THREAD)
                            .map(|i| {
                                journal
                                    .append_invoke(entry((t * PER_THREAD + i) as u8))
                                    .expect("every append succeeds")
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            threads
                .into_iter()
                .flat_map(|t| t.join().unwrap())
                .collect()
        });
        returned.sort_by_key(|r| r.seq);

        let total = THREADS * PER_THREAD;
        assert_eq!(returned.len(), total);
        assert_eq!(journal.len(), total as u64);
        let on_disk = journal.read_all().unwrap();
        assert_eq!(on_disk.len(), total);
        assert_eq!(Journal::verify_chain(&on_disk).unwrap(), total);
        for (i, (handed_back, written)) in returned.iter().zip(&on_disk).enumerate() {
            assert_eq!(
                handed_back.seq,
                i as u64 + 1,
                "sequence numbers run 1..=N with no gaps"
            );
            assert_eq!(
                handed_back, written,
                "the record returned to the caller is the record on disk"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A crash during a group commit can only cut the file mid-line, because
    /// the batch is one buffered write. That must cost the torn record and
    /// nothing else: the journal reopens, keeps appending, and still verifies.
    #[test]
    fn a_torn_final_line_is_trimmed_on_open() {
        let dir = tmp_dir("torn-tail");
        std::fs::remove_dir_all(&dir).ok();
        {
            let journal = Journal::open(&dir).unwrap();
            journal.append_invoke(entry(1)).unwrap();
            journal.append_invoke(entry(2)).unwrap();
        }
        let path = dir.join("journal.log");
        let mut raw = std::fs::read(&path).unwrap();
        raw.extend_from_slice(br#"{"seq":3,"ts_ms":1789112274191,"prev":"0000","kind":"inv"#);
        std::fs::write(&path, &raw).unwrap();
        assert!(
            Journal::read_all_from(&path).is_err(),
            "a torn line is not a record, so the strict reader must reject it"
        );

        let journal = Journal::open(&dir).unwrap();
        assert_eq!(journal.len(), 2, "the two intact records survive");
        journal.append_invoke(entry(3)).unwrap();
        let records = journal.read_all().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].seq, 3, "the next append reuses the torn seq");
        assert_eq!(Journal::verify_chain(&records).unwrap(), 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `witness attest` appends through its own handle while a proxy holds
    /// one open. A handle that trusted its cached tip would reuse a sequence
    /// number and break the chain, so it re-reads when the file has grown.
    #[test]
    fn a_second_handle_does_not_break_the_chain() {
        let dir = tmp_dir("two-writers");
        std::fs::remove_dir_all(&dir).ok();
        let serving = Journal::open(&dir).unwrap();
        serving.append_invoke(entry(1)).unwrap();

        // A separate handle, as a separate process would have.
        let attesting = Journal::open(&dir).unwrap();
        attesting.append_invoke(entry(2)).unwrap();

        // The first handle's cached tip is now stale; the next append must
        // pick up where the other writer left off.
        let third = serving.append_invoke(entry(3)).unwrap();
        assert_eq!(third.seq, 3);

        let records = journal_records(&dir);
        assert_eq!(records.len(), 3);
        assert_eq!(Journal::verify_chain(&records).unwrap(), 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Tolerating a torn tail must not become tolerating a damaged journal.
    /// Anything that parses as a complete line and still is not a record is
    /// corruption, wherever it sits, and opening must refuse.
    #[test]
    fn corruption_outside_the_torn_tail_is_still_fatal() {
        let dir = tmp_dir("corrupt-middle");
        std::fs::remove_dir_all(&dir).ok();
        {
            let journal = Journal::open(&dir).unwrap();
            for n in 1..=3 {
                journal.append_invoke(entry(n)).unwrap();
            }
        }
        let path = dir.join("journal.log");
        let intact: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();

        let mut damaged = intact.clone();
        damaged[1] = r#"{"seq":2,"not":"a record"}"#.into();
        std::fs::write(&path, format!("{}\n", damaged.join("\n"))).unwrap();
        let err = Journal::open(&dir).map(|_| ()).unwrap_err();
        assert!(
            format!("{err:#}").contains("line 2"),
            "the failure names the damaged line: {err:#}"
        );

        // Same story for the *last* line: complete, terminated, unparsable.
        let mut damaged = intact.clone();
        damaged[2] = r#"{"seq":3,"not":"a record"}"#.into();
        std::fs::write(&path, format!("{}\n", damaged.join("\n"))).unwrap();
        assert!(
            Journal::open(&dir).is_err(),
            "a finished line is corruption, not a torn write, even at the end"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    fn journal_records(dir: &Path) -> Vec<Record> {
        Journal::read_all_from(&dir.join("journal.log")).unwrap()
    }

    /// `n` appends pushed in hard enough from several threads that the writer
    /// sees batches rather than a stream of single records.
    fn burst(journal: &Journal, n: usize) {
        const THREADS: usize = 8;
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    for i in 0..n / THREADS {
                        journal.append_invoke(entry(i as u8)).unwrap();
                    }
                });
            }
        });
    }

    /// The stale-tip check guards the batch, not the record, so the case that
    /// has to hold is a foreign append landing between two batches. Bursts on
    /// either side make the batches real, and the chain must still come out
    /// contiguous across the record the other handle slipped in.
    #[test]
    fn a_second_handle_between_batches_does_not_break_the_chain() {
        const BURST: usize = 320;
        let dir = tmp_dir("two-writers-batched");
        std::fs::remove_dir_all(&dir).ok();
        let serving = Journal::open(&dir).unwrap();
        burst(&serving, BURST);

        // A separate handle, as a separate process would have.
        let attesting = Journal::open(&dir).unwrap();
        let foreign = attesting.append_invoke(entry(9)).unwrap();
        assert_eq!(foreign.seq, BURST as u64 + 1);

        burst(&serving, BURST);
        let records = journal_records(&dir);
        assert_eq!(records.len(), BURST * 2 + 1);
        assert_eq!(
            Journal::verify_chain(&records).unwrap(),
            BURST * 2 + 1,
            "the batch after the foreign append chains from it, not past it"
        );
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
