//! The execution boundary. `witness run -- <command> [args...]` runs a
//! command the way a shell would, and records what it *did* rather than only
//! what it was asked to do: the working directory is fingerprinted before and
//! after, and the difference between those two fingerprints is the record.
//!
//! The proxy records model calls and the MCP wrapper records tool calls; both
//! capture a conversation. A command is the point where a conversation turns
//! into a changed file, and that change is the thing an auditor actually wants
//! to see. So the journal entry for an exec carries a content-addressed
//! before-tree, an after-tree, the captured stdout and stderr, and an explicit
//! list of added, modified and deleted paths.
//!
//! Two honest boundaries, stated here because they shape everything below:
//! this observes effects inside `--dir` and nowhere else, and observation is
//! not containment. `--docker` adds containment, but a container is a sandbox,
//! not a proof; the record still describes what was observed, not what was
//! prevented.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Instant;

use crate::cas::Cas;
use crate::hash::{blake3_hex, canonical_json};
use crate::journal::{InvokeEntry, Journal, Record};

/// Journal `agent` for an execution when `--agent` is not given. A command has
/// no identity layer to read a Pact key from, so the boundary names itself.
pub const DEFAULT_AGENT: &str = "exec";

/// Journal `path` prefix, so one `witness audit` can tell a model call from a
/// tool call from an execution by prefix alone.
pub const PATH_PREFIX: &str = "exec:";

/// Directory names never walked. These are build output, dependency caches,
/// version control internals and witness's own store: high file counts, no
/// evidentiary value, and in the last case a self-referential loop.
pub const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", "witness-data"];

/// A tree larger than this is refused rather than silently hashed for
/// minutes. Narrowing `--dir` is almost always the right answer.
pub const MAX_FILES: usize = 50_000;

/// Files at or below this size are hashed with one read; larger ones are
/// streamed, so a multi-gigabyte artifact never has to fit in memory.
pub const STREAM_ABOVE: u64 = 64 * 1024 * 1024;

const STREAM_CHUNK: usize = 1024 * 1024;
const TEE_CHUNK: usize = 8 * 1024;

const SNAPSHOT_KIND: &str = "witness.exec.snapshot/1";
const INVOCATION_KIND: &str = "witness.exec.invocation/1";
const RESULT_KIND: &str = "witness.exec.result/1";

pub struct Options {
    pub data_dir: PathBuf,
    /// Directory to snapshot and run in. Defaults to the current directory.
    pub dir: Option<PathBuf>,
    /// Journal identity recorded for this execution.
    pub agent: String,
    /// Run inside this Docker image instead of on the host.
    pub docker: Option<String>,
    /// Walk dotfiles and dot-directories too. `SKIP_DIRS` still applies.
    pub include_hidden: bool,
    /// The command to run: program followed by its arguments.
    pub command: Vec<String>,
}

/// One file's identity in a snapshot. Size is carried alongside the hash
/// because it is free to collect and makes a diff readable without a lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    pub hash: String,
    pub size: u64,
}

/// A snapshot: relative path (always `/`-separated) to file identity. A
/// `BTreeMap` so the serialized manifest is sorted, and therefore so is its
/// content hash.
pub type Tree = BTreeMap<String, FileMeta>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

impl ChangeKind {
    fn symbol(self) -> char {
        match self {
            ChangeKind::Added => '+',
            ChangeKind::Modified => '~',
            ChangeKind::Deleted => '-',
        }
    }
}

/// One path's before-and-after. Absent sides are omitted rather than null, so
/// an added file carries no `old_*` keys at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub change: ChangeKind,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_size: Option<u64>,
}

/// The `req` object of an exec record: everything known before the command ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invocation {
    pub kind: String,
    /// The command as given, argv[0] first.
    pub argv: Vec<String>,
    /// Absolute working directory that was snapshotted.
    pub cwd: String,
    /// "host", or "docker:<image>".
    pub runtime: String,
    /// CAS hash of the snapshot manifest taken before the command ran.
    pub pre_snapshot: String,
    pub started_ms: u64,
}

/// The `resp` object of an exec record: everything the command turned out to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecResult {
    pub kind: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    /// CAS hash of the captured stdout, and its length in bytes.
    pub stdout: String,
    pub stdout_bytes: u64,
    pub stderr: String,
    pub stderr_bytes: u64,
    /// CAS hash of the snapshot manifest taken after the command ran.
    pub post_snapshot: String,
    pub added: usize,
    pub modified: usize,
    pub deleted: usize,
    pub diff: Vec<Change>,
}

/// The CAS object a snapshot hash resolves to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub kind: String,
    pub root: String,
    pub count: usize,
    pub files: Tree,
}

/// Names the walk refuses to descend into or record. `SKIP_DIRS` is
/// unconditional; everything else hidden depends on `--include-hidden`.
pub fn is_skipped(name: &str, include_hidden: bool) -> bool {
    SKIP_DIRS.contains(&name) || (!include_hidden && name.starts_with('.'))
}

/// `exec:<argv0 basename>`, so the journal stays readable when a program is
/// invoked by absolute path.
pub fn journal_path(program: &str) -> String {
    let name = Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(program);
    format!("{PATH_PREFIX}{name}")
}

/// `exec`, or `exec:docker:<image>` when the command ran in a container.
pub fn upstream_label(docker: Option<&str>) -> String {
    match docker {
        Some(image) => format!("exec:docker:{image}"),
        None => "exec".to_string(),
    }
}

/// Hash one file. Small files are read whole; anything over `STREAM_ABOVE` is
/// fed to the hasher a chunk at a time so peak memory stays flat.
fn hash_file(path: &Path, size: u64) -> Result<String> {
    if size <= STREAM_ABOVE {
        return Ok(blake3_hex(
            &fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        ));
    }
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; STREAM_CHUNK];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Walk `root` and fingerprint every regular file under it.
///
/// Symlinks are recorded as neither followed nor hashed: following them would
/// let a snapshot wander outside `--dir` and could cycle, so they are skipped
/// and the README says so. Empty directories leave no trace, because the unit
/// of evidence here is a file's content.
pub fn snapshot(root: &Path, include_hidden: bool) -> Result<Tree> {
    let mut tree = Tree::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("reading an entry of {}", dir.display()))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                // A non-UTF-8 name cannot be written to a JSON manifest, and
                // silently dropping it would be a lie about the tree.
                bail!(
                    "{} has a non-UTF-8 name and cannot be recorded; narrow --dir to exclude it",
                    entry.path().display()
                );
            };
            if is_skipped(name, include_hidden) {
                continue;
            }
            let path = entry.path();
            // symlink_metadata, so a link is classified as a link and not as
            // whatever it happens to point at.
            let meta =
                fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
            let file_type = meta.file_type();
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                // Sockets, fifos and devices have no content to diff.
                continue;
            }
            if tree.len() >= MAX_FILES {
                bail!(
                    "working directory holds more than {MAX_FILES} files; narrow it with --dir <subdirectory> so the snapshot stays fast and the diff stays readable"
                );
            }
            let rel = relative_key(root, &path);
            let hash = hash_file(&path, meta.len())?;
            tree.insert(
                rel,
                FileMeta {
                    hash,
                    size: meta.len(),
                },
            );
        }
    }
    Ok(tree)
}

/// A stable, `/`-separated key for a path under `root`, so a manifest recorded
/// on one platform reads the same on another.
fn relative_key(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// The difference between two snapshots, sorted by path. Identity is content
/// plus size, so a rewrite with identical bytes is correctly not a change.
pub fn diff(pre: &Tree, post: &Tree) -> Vec<Change> {
    let mut out = Vec::new();
    for (path, new) in post {
        match pre.get(path) {
            None => out.push(Change {
                change: ChangeKind::Added,
                path: path.clone(),
                old_hash: None,
                old_size: None,
                new_hash: Some(new.hash.clone()),
                new_size: Some(new.size),
            }),
            Some(old) if old != new => out.push(Change {
                change: ChangeKind::Modified,
                path: path.clone(),
                old_hash: Some(old.hash.clone()),
                old_size: Some(old.size),
                new_hash: Some(new.hash.clone()),
                new_size: Some(new.size),
            }),
            Some(_) => {}
        }
    }
    for (path, old) in pre {
        if !post.contains_key(path) {
            out.push(Change {
                change: ChangeKind::Deleted,
                path: path.clone(),
                old_hash: Some(old.hash.clone()),
                old_size: Some(old.size),
                new_hash: None,
                new_size: None,
            });
        }
    }
    // Paths are unique across the three kinds, so this is a total order.
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Map a completed execution onto the journal's invoke shape.
///
/// All three boundaries share one record type on purpose. `model` is None
/// because a command has no model; `cache` is always "miss" because a command
/// has side effects and serving one from a record would be a lie about what
/// happened; `status` follows the exit code, because that is the only success
/// signal a process gives.
pub fn build_entry(
    agent: &str,
    program: &str,
    upstream: &str,
    req: &str,
    resp: &str,
    exit_code: i32,
) -> InvokeEntry {
    InvokeEntry {
        agent: agent.to_string(),
        root: None,
        req: req.to_string(),
        resp: resp.to_string(),
        path: journal_path(program),
        model: None,
        upstream: upstream.to_string(),
        cache: "miss".into(),
        status: if exit_code == 0 { 200 } else { 500 },
        sig: None,
    }
}

/// Store a value as canonical JSON and return its hash.
fn put_json<T: Serialize>(cas: &Cas, value: &T) -> Result<String> {
    let value = serde_json::to_value(value).context("serializing manifest")?;
    cas.put(&canonical_json(&value))
}

/// Extra CAS objects an exec record reaches through its result manifest.
///
/// `witness audit` greps `req` and `resp` directly, but for an execution those
/// are manifests that *name* the output rather than contain it. Following the
/// two hashes here is what makes "which run printed this string" answerable.
/// Anything unreadable yields nothing: audit degrades, it never fails.
pub fn linked_objects(cas: &Cas, record: &Record) -> Vec<(&'static str, String)> {
    if !record.path.starts_with(PATH_PREFIX) {
        return Vec::new();
    }
    let Ok(Some(bytes)) = cas.get(&record.resp) else {
        return Vec::new();
    };
    let Ok(result) = serde_json::from_slice::<ExecResult>(&bytes) else {
        return Vec::new();
    };
    vec![("stdout", result.stdout), ("stderr", result.stderr)]
}

/// Copy `src` to `dst` chunk by chunk, keeping a copy. The user sees their
/// command's output live; witness gets the bytes for the record.
fn tee<R, W>(mut src: R, mut dst: W) -> std::thread::JoinHandle<Vec<u8>>
where
    R: Read + Send + 'static,
    W: IoWrite + Send + 'static,
{
    std::thread::spawn(move || {
        let mut captured = Vec::new();
        let mut buf = [0u8; TEE_CHUNK];
        loop {
            match src.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // Write through before recording: nothing the user is
                    // watching should wait on our bookkeeping.
                    let _ = dst.write_all(&buf[..n]);
                    let _ = dst.flush();
                    captured.extend_from_slice(&buf[..n]);
                }
            }
        }
        captured
    })
}

/// The exit code to propagate. A process killed by a signal has no code, so
/// report it the way a shell does rather than inventing a plain failure.
fn exit_code(status: &ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

/// Fail early and legibly when `--docker` is asked for and Docker is not
/// there. This runs before the snapshot so nothing is written on a dead end.
fn require_docker() -> Result<()> {
    match Command::new("docker")
        .arg("info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => bail!(
            "docker is on PATH but `docker info` failed, so the daemon is not running. Start Docker Desktop, colima, or your equivalent, or drop --docker to run on the host."
        ),
        Err(e) => bail!(
            "docker is not available ({e}). Install it, or drop --docker to run on the host."
        ),
    }
}

/// Run the command to completion and record what it changed. Returns the
/// command's exit code so a caller sees the process it thinks it launched.
pub fn run(opts: Options) -> Result<i32> {
    let (program, args) = opts
        .command
        .split_first()
        .context("no command given (use: witness run -- <command> [args...])")?;

    let workdir = match &opts.dir {
        Some(dir) => dir.clone(),
        None => std::env::current_dir().context("reading the current directory")?,
    };
    let workdir = fs::canonicalize(&workdir)
        .with_context(|| format!("working directory {} is not readable", workdir.display()))?;
    if !workdir.is_dir() {
        bail!("{} is not a directory", workdir.display());
    }

    // Fail before touching anything if the store is not writable, and before
    // snapshotting if the container runtime is missing.
    let cas = Cas::open(&opts.data_dir).context("opening CAS")?;
    let journal = Journal::open(&opts.data_dir).context("opening journal")?;
    if opts.docker.is_some() {
        require_docker()?;
    }

    let pre = snapshot(&workdir, opts.include_hidden).context("snapshotting before the command")?;
    let pre_hash = put_json(
        &cas,
        &SnapshotManifest {
            kind: SNAPSHOT_KIND.into(),
            root: workdir.display().to_string(),
            count: pre.len(),
            files: pre.clone(),
        },
    )
    .context("storing the before snapshot")?;

    let mut cmd = match &opts.docker {
        Some(image) => {
            let mut cmd = Command::new("docker");
            cmd.arg("run")
                .arg("--rm")
                .arg("-v")
                .arg(format!("{}:/work", workdir.display()))
                .arg("-w")
                .arg("/work")
                .arg(image)
                .arg(program)
                .args(args);
            cmd
        }
        None => {
            let mut cmd = Command::new(program);
            cmd.args(args).current_dir(&workdir);
            cmd
        }
    };
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let started_ms = crate::journal::now_ms();
    let clock = Instant::now();
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning '{program}'"))?;
    let out_tee = tee(
        child.stdout.take().expect("stdout was piped"),
        std::io::stdout(),
    );
    let err_tee = tee(
        child.stderr.take().expect("stderr was piped"),
        std::io::stderr(),
    );
    let status = child.wait().context("waiting for the command")?;
    let stdout = out_tee
        .join()
        .map_err(|_| anyhow::anyhow!("the stdout capture thread panicked"))?;
    let stderr = err_tee
        .join()
        .map_err(|_| anyhow::anyhow!("the stderr capture thread panicked"))?;
    let duration_ms = clock.elapsed().as_millis() as u64;
    let code = exit_code(&status);

    let post = snapshot(&workdir, opts.include_hidden).context("snapshotting after the command")?;
    let post_hash = put_json(
        &cas,
        &SnapshotManifest {
            kind: SNAPSHOT_KIND.into(),
            root: workdir.display().to_string(),
            count: post.len(),
            files: post.clone(),
        },
    )
    .context("storing the after snapshot")?;

    let changes = diff(&pre, &post);
    let counts = |kind: ChangeKind| changes.iter().filter(|c| c.change == kind).count();

    let mut argv = vec![program.clone()];
    argv.extend(args.iter().cloned());
    let req = put_json(
        &cas,
        &Invocation {
            kind: INVOCATION_KIND.into(),
            argv,
            cwd: workdir.display().to_string(),
            runtime: match &opts.docker {
                Some(image) => format!("docker:{image}"),
                None => "host".into(),
            },
            pre_snapshot: pre_hash,
            started_ms,
        },
    )
    .context("storing the invocation manifest")?;

    let stdout_hash = cas.put(&stdout).context("storing stdout")?;
    let stderr_hash = cas.put(&stderr).context("storing stderr")?;
    let resp = put_json(
        &cas,
        &ExecResult {
            kind: RESULT_KIND.into(),
            exit_code: code,
            duration_ms,
            stdout: stdout_hash,
            stdout_bytes: stdout.len() as u64,
            stderr: stderr_hash,
            stderr_bytes: stderr.len() as u64,
            post_snapshot: post_hash,
            added: counts(ChangeKind::Added),
            modified: counts(ChangeKind::Modified),
            deleted: counts(ChangeKind::Deleted),
            diff: changes.clone(),
        },
    )
    .context("storing the result manifest")?;

    let upstream = upstream_label(opts.docker.as_deref());
    let record = journal
        .append_invoke(build_entry(
            &opts.agent,
            program,
            &upstream,
            &req,
            &resp,
            code,
        ))
        .context("appending the execution to the journal")?;

    eprintln!(
        "witness run: exit {code} after {duration_ms}ms, {} file change(s) in {} (+{} ~{} -{})",
        changes.len(),
        workdir.display(),
        counts(ChangeKind::Added),
        counts(ChangeKind::Modified),
        counts(ChangeKind::Deleted),
    );
    eprintln!(
        "witness run: journal seq {} (`witness diff --seq {}` lists them)",
        record.seq, record.seq
    );
    Ok(code)
}

/// Pretty-print one execution record's side effects, reading the invocation
/// and result manifests back out of the CAS.
pub fn show_diff(data_dir: &Path, seq: u64) -> Result<()> {
    let records = Journal::read_all_from(&data_dir.join("journal.log"))?;
    Journal::verify_chain(&records).context("journal chain broken, diff unreliable")?;
    let record = records
        .iter()
        .find(|r| r.seq == seq)
        .with_context(|| format!("no journal record with seq {seq}"))?;
    if !record.path.starts_with(PATH_PREFIX) {
        bail!(
            "seq {seq} is a {} record, not an execution; `witness diff` only reads {PATH_PREFIX}* records",
            record.path
        );
    }
    let cas = Cas::open(data_dir)?;
    let invocation: Invocation = load(&cas, &record.req, "invocation manifest")?;
    let result: ExecResult = load(&cas, &record.resp, "result manifest")?;

    println!(
        "seq {}  {}  agent={}",
        record.seq, record.path, record.agent
    );
    println!("argv:     {}", invocation.argv.join(" "));
    println!("cwd:      {}", invocation.cwd);
    println!("runtime:  {}", invocation.runtime);
    println!("exit:     {} ({}ms)", result.exit_code, result.duration_ms);
    println!(
        "stdout:   {} ({} bytes)",
        &result.stdout[..12],
        result.stdout_bytes
    );
    println!(
        "stderr:   {} ({} bytes)",
        &result.stderr[..12],
        result.stderr_bytes
    );
    println!(
        "changes:  {} (+{} ~{} -{})",
        result.diff.len(),
        result.added,
        result.modified,
        result.deleted
    );
    for change in &result.diff {
        let detail = match (&change.old_hash, &change.new_hash) {
            (Some(old), Some(new)) => format!("{} -> {}", &old[..12], &new[..12]),
            (None, Some(new)) => format!("{} ({} bytes)", &new[..12], change.new_size.unwrap_or(0)),
            (Some(old), None) => format!(
                "{} (was {} bytes)",
                &old[..12],
                change.old_size.unwrap_or(0)
            ),
            (None, None) => String::new(),
        };
        println!("  {} {}  {}", change.change.symbol(), change.path, detail);
    }
    if result.diff.is_empty() {
        println!("  (the command changed no file under the recorded directory)");
    }
    Ok(())
}

fn load<T: for<'de> Deserialize<'de>>(cas: &Cas, hash: &str, what: &str) -> Result<T> {
    let bytes = cas
        .get(hash)?
        .with_context(|| format!("{what} {hash} is missing from the store"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("{hash} is not a {what}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(content: &str) -> FileMeta {
        FileMeta {
            hash: blake3_hex(content.as_bytes()),
            size: content.len() as u64,
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("witness-exec-unit-{tag}-{}", std::process::id()))
    }

    #[test]
    fn skip_list_covers_build_output_and_our_own_store() {
        for name in SKIP_DIRS {
            assert!(is_skipped(name, false), "{name} must be skipped");
            // Even --include-hidden does not resurrect these: they are
            // skipped for being noise, not for being hidden.
            assert!(is_skipped(name, true), "{name} must stay skipped");
        }
        assert!(is_skipped(".env", false));
        assert!(
            !is_skipped(".env", true),
            "--include-hidden reaches dotfiles"
        );
        assert!(!is_skipped("src", false));
        assert!(!is_skipped("target.txt", false), "prefix is not a match");
    }

    #[test]
    fn journal_path_and_upstream_label_stay_readable() {
        assert_eq!(journal_path("sh"), "exec:sh");
        assert_eq!(journal_path("/usr/bin/make"), "exec:make");
        assert_eq!(journal_path("./build.sh"), "exec:build.sh");
        assert_eq!(upstream_label(None), "exec");
        assert_eq!(upstream_label(Some("rust:1.85")), "exec:docker:rust:1.85");
    }

    #[test]
    fn diff_classifies_every_kind_of_change() {
        let mut pre = Tree::new();
        pre.insert("keep.txt".into(), meta("same"));
        pre.insert("gone.txt".into(), meta("bye"));
        pre.insert("nested/deep/old.txt".into(), meta("one"));

        let mut post = pre.clone();
        post.remove("gone.txt");
        post.insert("nested/deep/old.txt".into(), meta("two"));
        post.insert("nested/deep/new.txt".into(), meta("fresh"));

        let changes = diff(&pre, &post);
        assert_eq!(
            changes.len(),
            3,
            "keep.txt is unchanged and must not appear"
        );
        // Sorted by path, so the order is stable across runs and platforms.
        assert_eq!(changes[0].path, "gone.txt");
        assert_eq!(changes[0].change, ChangeKind::Deleted);
        assert_eq!(changes[0].old_hash, Some(meta("bye").hash));
        assert_eq!(changes[0].new_hash, None);

        assert_eq!(changes[1].path, "nested/deep/new.txt");
        assert_eq!(changes[1].change, ChangeKind::Added);
        assert_eq!(changes[1].old_hash, None);
        assert_eq!(changes[1].new_hash, Some(meta("fresh").hash));

        assert_eq!(changes[2].path, "nested/deep/old.txt");
        assert_eq!(changes[2].change, ChangeKind::Modified);
        assert_eq!(changes[2].old_hash, Some(meta("one").hash));
        assert_eq!(changes[2].new_hash, Some(meta("two").hash));
    }

    #[test]
    fn a_rewrite_with_identical_bytes_is_not_a_change() {
        let mut pre = Tree::new();
        pre.insert("a.txt".into(), meta("hello"));
        let post = pre.clone();
        assert!(diff(&pre, &post).is_empty());
    }

    #[test]
    fn snapshot_walks_nested_dirs_and_honours_the_skip_list() {
        let dir = tmp_dir("walk");
        std::fs::remove_dir_all(&dir).ok();
        for sub in [
            "nested/deep",
            ".git/objects",
            "node_modules/pkg",
            "target/debug",
            ".hidden",
        ] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        fs::write(dir.join("top.txt"), "top").unwrap();
        fs::write(dir.join("nested/mid.txt"), "mid").unwrap();
        fs::write(dir.join("nested/deep/leaf.txt"), "leaf").unwrap();
        fs::write(dir.join(".git/objects/blob"), "git internals").unwrap();
        fs::write(dir.join("node_modules/pkg/index.js"), "deps").unwrap();
        fs::write(dir.join("target/debug/bin"), "build output").unwrap();
        fs::write(dir.join(".hidden/secret"), "dotdir").unwrap();
        fs::write(dir.join(".dotfile"), "dotfile").unwrap();

        let tree = snapshot(&dir, false).unwrap();
        let paths: Vec<&str> = tree.keys().map(String::as_str).collect();
        assert_eq!(
            paths,
            vec!["nested/deep/leaf.txt", "nested/mid.txt", "top.txt"],
            "walk must be recursive, sorted, and skip-listed"
        );
        assert_eq!(tree["top.txt"], meta("top"));
        assert_eq!(tree["nested/deep/leaf.txt"], meta("leaf"));

        // --include-hidden reaches dotfiles and dot-directories, but never
        // .git, node_modules or target.
        let hidden = snapshot(&dir, true).unwrap();
        let paths: Vec<&str> = hidden.keys().map(String::as_str).collect();
        assert_eq!(
            paths,
            vec![
                ".dotfile",
                ".hidden/secret",
                "nested/deep/leaf.txt",
                "nested/mid.txt",
                "top.txt"
            ]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_real_snapshots_diff_into_the_recorded_change_list() {
        let dir = tmp_dir("realdiff");
        std::fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(dir.join("nested")).unwrap();
        fs::write(dir.join("keep.txt"), "keep").unwrap();
        fs::write(dir.join("deleted.txt"), "doomed").unwrap();
        fs::write(dir.join("nested/modified.txt"), "before").unwrap();

        let pre = snapshot(&dir, false).unwrap();
        fs::remove_file(dir.join("deleted.txt")).unwrap();
        fs::write(dir.join("nested/modified.txt"), "after").unwrap();
        fs::write(dir.join("nested/created.txt"), "new").unwrap();
        let post = snapshot(&dir, false).unwrap();

        let changes = diff(&pre, &post);
        let summary: Vec<(ChangeKind, &str)> = changes
            .iter()
            .map(|c| (c.change, c.path.as_str()))
            .collect();
        assert_eq!(
            summary,
            vec![
                (ChangeKind::Deleted, "deleted.txt"),
                (ChangeKind::Added, "nested/created.txt"),
                (ChangeKind::Modified, "nested/modified.txt"),
            ]
        );
        assert_eq!(changes[2].new_hash, Some(meta("after").hash));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn entry_maps_onto_the_existing_invoke_shape() {
        let ok = build_entry("exec", "sh", "exec", &"aa".repeat(32), &"bb".repeat(32), 0);
        assert_eq!(ok.agent, "exec");
        assert_eq!(ok.path, "exec:sh");
        assert_eq!(ok.upstream, "exec");
        assert_eq!(ok.cache, "miss");
        assert_eq!(ok.status, 200);
        assert_eq!(ok.model, None);
        assert_eq!(ok.root, None);
        assert_eq!(ok.sig, None);

        // Any nonzero exit is a 500, which is how `witness log` and `stats`
        // already read failure.
        let failed = build_entry("ci", "make", "exec", &"aa".repeat(32), &"bb".repeat(32), 7);
        assert_eq!(failed.status, 500);
        assert_eq!(failed.agent, "ci");
    }

    /// Large files must not be read into memory whole, and the streaming path
    /// must agree with the one-shot path on the same bytes.
    #[test]
    fn streamed_and_one_shot_hashes_agree() {
        let dir = tmp_dir("stream");
        std::fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blob.bin");
        let bytes: Vec<u8> = (0..(STREAM_CHUNK * 2 + 7))
            .map(|i| (i % 251) as u8)
            .collect();
        fs::write(&path, &bytes).unwrap();
        let size = bytes.len() as u64;
        // Force the streaming branch by claiming the file is over the limit.
        assert_eq!(
            hash_file(&path, STREAM_ABOVE + 1).unwrap(),
            hash_file(&path, size).unwrap()
        );
        assert_eq!(hash_file(&path, size).unwrap(), blake3_hex(&bytes));
        std::fs::remove_dir_all(&dir).ok();
    }
}
