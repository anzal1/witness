//! End-to-end for the execution boundary: a real `witness run` process
//! wrapping a real command, checked through the same journal, CAS, audit and
//! chain-verification surface the model and tool boundaries use.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use witness::exec::{ChangeKind, ExecResult, Invocation, SnapshotManifest};
use witness::hash::blake3_hex;
use witness::journal::Journal;

/// The scenario the layer exists for: a command that prints on both streams,
/// creates a file, deletes a file, appends to a file, and fails.
const SCRIPT: &str = "echo out; echo err >&2; echo new > created.txt; rm deleted.txt; echo changed >> modified.txt; exit 7";

fn scratch(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("witness-exec-e2e-{tag}-{}", std::process::id()))
}

/// A working directory with a little of everything: files that will change,
/// a file that will not, a nested subtree, and three directories the snapshot
/// is supposed to ignore.
fn seed_workdir(work: &Path) {
    std::fs::remove_dir_all(work).ok();
    for sub in ["nested", ".git", "node_modules", "target"] {
        std::fs::create_dir_all(work.join(sub)).unwrap();
    }
    std::fs::write(work.join("deleted.txt"), "doomed\n").unwrap();
    std::fs::write(work.join("modified.txt"), "before\n").unwrap();
    std::fs::write(work.join("keep.txt"), "untouched\n").unwrap();
    std::fs::write(work.join("nested/inner.txt"), "deep\n").unwrap();
    std::fs::write(work.join(".git/config"), "vcs internals\n").unwrap();
    std::fs::write(work.join("node_modules/index.js"), "dependency\n").unwrap();
    std::fs::write(work.join("target/artifact"), "build output\n").unwrap();
}

fn witness(data_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_witness"))
        .arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("running witness")
}

fn result_of(data_dir: &Path, resp_hash: &str) -> ExecResult {
    let cas = witness::cas::Cas::open(data_dir).unwrap();
    serde_json::from_slice(&cas.get(resp_hash).unwrap().unwrap()).unwrap()
}

#[test]
fn a_failed_command_is_recorded_with_everything_it_changed() {
    let root = scratch("run");
    let work = root.join("work");
    let data = root.join("witness-store");
    seed_workdir(&work);

    let out = witness(
        &data,
        &[
            "run",
            "--dir",
            work.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            SCRIPT,
        ],
    );

    // 1. The command's exit code is the wrapper's exit code.
    assert_eq!(out.status.code(), Some(7), "exit code must propagate");
    // 2. The user still saw the command's own output, live, on both streams.
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "out\n");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.starts_with("err\n"), "stderr passthrough: {stderr}");
    assert!(stderr.contains("witness run: exit 7"), "summary: {stderr}");

    // 3. One journal record, and it verifies as part of the same chain.
    let records = Journal::read_all_from(&data.join("journal.log")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(Journal::verify_chain(&records).unwrap(), 1);
    let record = &records[0];
    assert_eq!(record.kind, "invoke");
    assert_eq!(record.path, "exec:sh");
    assert_eq!(record.agent, "exec");
    assert_eq!(record.upstream, "exec");
    assert_eq!(record.cache, "miss");
    assert_eq!(record.model, None);
    assert_eq!(record.status, 500, "a nonzero exit is a 500");

    // 4. The result manifest lists exactly the three changed paths, with the
    //    hashes of the bytes that were actually on disk on each side.
    let result = result_of(&data, &record.resp);
    assert_eq!(result.exit_code, 7);
    assert_eq!((result.added, result.modified, result.deleted), (1, 1, 1));
    let changes: Vec<(ChangeKind, &str)> = result
        .diff
        .iter()
        .map(|c| (c.change, c.path.as_str()))
        .collect();
    assert_eq!(
        changes,
        vec![
            (ChangeKind::Added, "created.txt"),
            (ChangeKind::Deleted, "deleted.txt"),
            (ChangeKind::Modified, "modified.txt"),
        ],
        "keep.txt, nested/inner.txt and the skipped trees must not appear"
    );

    let created = &result.diff[0];
    assert_eq!(
        created.new_hash.as_deref(),
        Some(blake3_hex(b"new\n").as_str())
    );
    assert_eq!(created.new_size, Some(4));
    assert_eq!(created.old_hash, None);

    let deleted = &result.diff[1];
    assert_eq!(
        deleted.old_hash.as_deref(),
        Some(blake3_hex(b"doomed\n").as_str())
    );
    assert_eq!(deleted.new_hash, None);

    let modified = &result.diff[2];
    assert_eq!(
        modified.old_hash.as_deref(),
        Some(blake3_hex(b"before\n").as_str())
    );
    assert_eq!(
        modified.new_hash.as_deref(),
        Some(blake3_hex(b"before\nchanged\n").as_str())
    );

    // 5. The CAS holds the captured streams verbatim.
    let cas = witness::cas::Cas::open(&data).unwrap();
    assert_eq!(cas.get(&result.stdout).unwrap().unwrap(), b"out\n");
    assert_eq!(cas.get(&result.stderr).unwrap().unwrap(), b"err\n");
    assert_eq!((result.stdout_bytes, result.stderr_bytes), (4, 4));

    // 6. Both snapshots resolve, and the skip list held on the way in.
    let invocation: Invocation =
        serde_json::from_slice(&cas.get(&record.req).unwrap().unwrap()).unwrap();
    assert_eq!(invocation.argv, vec!["sh", "-c", SCRIPT]);
    assert_eq!(invocation.runtime, "host");
    assert!(invocation.cwd.ends_with("work"), "cwd: {}", invocation.cwd);

    let pre: SnapshotManifest =
        serde_json::from_slice(&cas.get(&invocation.pre_snapshot).unwrap().unwrap()).unwrap();
    let post: SnapshotManifest =
        serde_json::from_slice(&cas.get(&result.post_snapshot).unwrap().unwrap()).unwrap();
    let before: Vec<&str> = pre.files.keys().map(String::as_str).collect();
    assert_eq!(
        before,
        vec![
            "deleted.txt",
            "keep.txt",
            "modified.txt",
            "nested/inner.txt"
        ],
        ".git, node_modules and target are never walked"
    );
    assert_eq!(pre.count, 4);
    assert_eq!(post.count, 4, "one file went, one arrived");
    assert!(post.files.contains_key("created.txt"));
    assert!(!post.files.contains_key("deleted.txt"));

    // 7. `witness verify` agrees from the outside.
    let verify = witness(&data, &["verify"]);
    assert!(verify.status.success());
    assert!(String::from_utf8(verify.stdout)
        .unwrap()
        .contains("1 records"));

    std::fs::remove_dir_all(&root).ok();
}

/// The whole point of recording stdout into the same store: a grep over the
/// journal reaches what a command printed, not just what it was asked to do.
#[test]
fn audit_finds_text_a_recorded_command_printed() {
    let root = scratch("audit");
    let work = root.join("work");
    let data = root.join("witness-store");
    seed_workdir(&work);

    let out = witness(
        &data,
        &[
            "run",
            "--dir",
            work.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            SCRIPT,
        ],
    );
    assert_eq!(out.status.code(), Some(7));

    let audit = witness(&data, &["audit", "--contains", "out"]);
    assert!(audit.status.success());
    let report = String::from_utf8(audit.stdout).unwrap();
    assert!(
        report.contains("MATCH seq 1 stdout"),
        "audit must follow the result manifest into the captured stdout, got: {report}"
    );

    // A string that was never printed and never argued stays a clean negative.
    let audit = witness(&data, &["audit", "--contains", "the capital of Peru"]);
    assert!(String::from_utf8(audit.stdout)
        .unwrap()
        .contains("no record"));

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn diff_prints_the_recorded_change_list() {
    let root = scratch("diff");
    let work = root.join("work");
    let data = root.join("witness-store");
    seed_workdir(&work);

    witness(
        &data,
        &[
            "run",
            "--dir",
            work.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            SCRIPT,
        ],
    );

    let out = witness(&data, &["diff", "--seq", "1"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = String::from_utf8(out.stdout).unwrap();
    assert!(report.contains("seq 1  exec:sh  agent=exec"), "{report}");
    assert!(report.contains("exit:     7"), "{report}");
    assert!(report.contains("runtime:  host"), "{report}");
    assert!(report.contains("changes:  3 (+1 ~1 -1)"), "{report}");
    assert!(report.contains("+ created.txt"), "{report}");
    assert!(report.contains("- deleted.txt"), "{report}");
    assert!(report.contains("~ modified.txt"), "{report}");
    assert!(!report.contains("keep.txt"), "{report}");

    // `witness diff` is for execution records only, and says so.
    let out = witness(&data, &["diff", "--seq", "99"]);
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr)
        .unwrap()
        .contains("no journal record with seq 99"));

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn a_command_that_changes_nothing_is_still_recorded() {
    let root = scratch("noop");
    let work = root.join("work");
    let data = root.join("witness-store");
    seed_workdir(&work);

    let out = witness(
        &data,
        &[
            "run",
            "--dir",
            work.to_str().unwrap(),
            "--agent",
            "ci",
            "--",
            "true",
        ],
    );
    assert_eq!(out.status.code(), Some(0));

    let records = Journal::read_all_from(&data.join("journal.log")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, 200);
    assert_eq!(records[0].agent, "ci");
    assert_eq!(records[0].path, "exec:true");
    let result = result_of(&data, &records[0].resp);
    assert!(result.diff.is_empty());
    assert_eq!((result.added, result.modified, result.deleted), (0, 0, 0));

    std::fs::remove_dir_all(&root).ok();
}

/// Docker is optional on a developer machine and absent on plenty of CI
/// runners, so this test reports a skip rather than failing the suite.
///
/// Three things have to hold, and each gets its own skip note: a daemon must
/// answer, the image must be obtainable, and the runtime must actually share
/// `probe` with the container. The last one bites on macOS, where Docker runs
/// in a VM that mounts only some host paths, and a bind of an unshared
/// directory silently presents an empty one rather than failing.
fn docker_ready(image: &str, probe: &Path) -> bool {
    let quiet = |args: &[&str]| {
        Command::new("docker")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if !quiet(&["info"]) {
        eprintln!("SKIP docker test: `docker info` failed, no daemon available");
        return false;
    }
    if !quiet(&["image", "inspect", image]) && !quiet(&["pull", image]) {
        eprintln!("SKIP docker test: image {image} is not local and could not be pulled");
        return false;
    }
    std::fs::create_dir_all(probe).unwrap();
    std::fs::write(probe.join("mount-probe"), "shared\n").unwrap();
    let shared = quiet(&[
        "run",
        "--rm",
        "-v",
        &format!("{}:/work", probe.display()),
        "-w",
        "/work",
        image,
        "test",
        "-f",
        "mount-probe",
    ]);
    std::fs::remove_file(probe.join("mount-probe")).ok();
    if !shared {
        eprintln!(
            "SKIP docker test: the runtime does not share {} with containers, so a bind mount there sees an empty directory. On colima, `colima start --mount {}:w`.",
            probe.display(),
            std::env::temp_dir().display()
        );
        return false;
    }
    true
}

#[test]
fn a_containerised_command_is_recorded_through_the_bind_mount() {
    const IMAGE: &str = "alpine:3";
    let root = scratch("docker");
    let work = root.join("work");
    let data = root.join("witness-store");
    if !docker_ready(IMAGE, &work) {
        std::fs::remove_dir_all(&root).ok();
        return;
    }
    seed_workdir(&work);

    let out = witness(
        &data,
        &[
            "run",
            "--dir",
            work.to_str().unwrap(),
            "--docker",
            IMAGE,
            "--",
            "sh",
            "-c",
            "echo from-the-container > in-container.txt; rm deleted.txt; exit 3",
        ],
    );
    assert_eq!(out.status.code(), Some(3), "container exit code propagates");

    let records = Journal::read_all_from(&data.join("journal.log")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(Journal::verify_chain(&records).unwrap(), 1);
    assert_eq!(records[0].upstream, format!("exec:docker:{IMAGE}"));
    assert_eq!(records[0].status, 500);

    let result = result_of(&data, &records[0].resp);
    let changes: Vec<(ChangeKind, &str)> = result
        .diff
        .iter()
        .map(|c| (c.change, c.path.as_str()))
        .collect();
    assert_eq!(
        changes,
        vec![
            (ChangeKind::Deleted, "deleted.txt"),
            (ChangeKind::Added, "in-container.txt"),
        ],
        "the host sees the container's writes through the bind mount"
    );

    let cas = witness::cas::Cas::open(&data).unwrap();
    let invocation: Invocation =
        serde_json::from_slice(&cas.get(&records[0].req).unwrap().unwrap()).unwrap();
    assert_eq!(invocation.runtime, format!("docker:{IMAGE}"));

    std::fs::remove_dir_all(&root).ok();
}
