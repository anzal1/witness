//! End-to-end for the tool boundary: a real `witness mcp` process wrapping a
//! fake stdio MCP server, checked through the same journal, CAS and audit
//! surface the model boundary uses.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use witness::journal::Journal;

/// A stdio MCP server in a dozen lines: reads newline-delimited JSON-RPC,
/// answers anything with an id, stays silent for notifications. `explode`
/// returns a JSON-RPC error so the failure mapping is exercised too.
const FAKE_SERVER: &str = r#"
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    if mid is None:
        continue
    if msg.get("method") == "tools/call":
        name = msg["params"]["name"]
        if name == "explode":
            out = {"jsonrpc": "2.0", "id": mid,
                   "error": {"code": -32000, "message": "the tool blew up"}}
        else:
            out = {"jsonrpc": "2.0", "id": mid, "result": {"content": [
                {"type": "text", "text": "the capital of France is Paris"}]}}
    else:
        out = {"jsonrpc": "2.0", "id": mid, "result": {"ok": True}}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
"#;

fn data_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("witness-mcp-e2e-{tag}-{}", std::process::id()))
}

/// Drive one wrapped session: feed `client_lines` to `witness mcp`, close
/// stdin, and return what the client would have seen on stdout plus the
/// wrapper's own stderr summary.
fn run_session(dir: &Path, agent: &str, client_lines: &[&str]) -> (String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_witness"))
        .arg("--data-dir")
        .arg(dir)
        .arg("mcp")
        .arg("--agent")
        .arg(agent)
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(FAKE_SERVER)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning witness mcp");

    {
        let stdin = child.stdin.as_mut().unwrap();
        for line in client_lines {
            writeln!(stdin, "{line}").unwrap();
        }
    }
    // Dropping stdin closes it, which is the spec's shutdown signal.
    drop(child.stdin.take());

    let out = child.wait_with_output().expect("waiting for witness mcp");
    assert!(
        out.status.success(),
        "witness mcp exited with {}",
        out.status
    );
    (
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn session_lines() -> Vec<&'static str> {
    vec![
        // Handshake and discovery: forwarded, never recorded in v1.
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28"}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        // Two tool calls: one succeeds, one returns a JSON-RPC error. The
        // second uses a string id, which must not collide with the number 4.
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"lookup","arguments":{"q":"capital of France"}}}"#,
        r#"{"jsonrpc":"2.0","id":"4","method":"tools/call","params":{"name":"explode","arguments":{}}}"#,
    ]
}

#[test]
fn wrapped_session_records_exactly_the_tool_calls() {
    let dir = data_dir("calls");
    std::fs::remove_dir_all(&dir).ok();
    let (stdout, stderr) = run_session(&dir, "agent-under-test", &session_lines());

    // 1. The client sees every reply, untouched. Four requests carried an id;
    //    the notification is answered by nothing.
    let replies: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(replies.len(), 4, "transparent piping, got: {stdout}");
    assert!(replies[3].contains("the tool blew up"));

    // 2. The journal gained the two tool calls and nothing else.
    let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
    assert_eq!(records.len(), 2, "only tools/call is recorded in v1");
    assert_eq!(Journal::verify_chain(&records).unwrap(), 2);

    let ok = &records[0];
    assert_eq!(ok.kind, "invoke");
    assert_eq!(ok.path, "mcp:tools/call:lookup");
    assert_eq!(ok.agent, "agent-under-test");
    assert_eq!(ok.upstream, "mcp:python3");
    assert_eq!(ok.cache, "miss");
    assert_eq!(ok.status, 200);
    assert_eq!(ok.model, None);

    let failed = &records[1];
    assert_eq!(failed.path, "mcp:tools/call:explode");
    assert_eq!(failed.status, 500, "a JSON-RPC error envelope is a 500");

    // 3. The CAS holds both full bodies, and the journal hashes resolve to
    //    them: the same audit path the model boundary relies on.
    let cas = witness::cas::Cas::open(&dir).unwrap();
    let req = String::from_utf8(cas.get(&ok.req).unwrap().unwrap()).unwrap();
    let resp = String::from_utf8(cas.get(&ok.resp).unwrap().unwrap()).unwrap();
    assert!(req.contains(r#""name":"lookup""#), "stored request: {req}");
    assert!(req.contains("capital of France"));
    assert!(resp.contains("the capital of France is Paris"));
    // Bodies are the exact wire frames, with no line terminator attached.
    assert!(!resp.ends_with('\n'));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&resp).unwrap()["id"],
        3
    );

    // 4. Non-tool traffic is counted, not recorded: initialize, the
    //    initialized notification, tools/list, and the two replies that came
    //    back for the two id-bearing ones.
    assert!(
        stderr.contains("2 tool call(s) recorded, 5 other message(s) passed through unrecorded"),
        "summary line missing, stderr was: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// `witness audit` works across the tool boundary by construction: same
/// journal, same CAS, no new code path.
#[test]
fn audit_finds_a_string_inside_a_recorded_tool_response() {
    let dir = data_dir("audit");
    std::fs::remove_dir_all(&dir).ok();
    run_session(&dir, "mcp-client", &session_lines());

    let out = Command::new(env!("CARGO_BIN_EXE_witness"))
        .arg("--data-dir")
        .arg(&dir)
        .arg("audit")
        .arg("--contains")
        .arg("the capital of France is Paris")
        .output()
        .expect("running witness audit");
    assert!(out.status.success());
    let report = String::from_utf8(out.stdout).unwrap();

    assert!(
        report.contains("MATCH seq 1 response"),
        "audit must find the tool response body, got: {report}"
    );
    assert!(report.contains("agent=mcp-client"));
    assert!(report.contains("1 match(es)"));

    // A string that was never on the wire stays a clean negative.
    let out = Command::new(env!("CARGO_BIN_EXE_witness"))
        .arg("--data-dir")
        .arg(&dir)
        .arg("audit")
        .arg("--contains")
        .arg("the capital of Peru")
        .output()
        .unwrap();
    assert!(String::from_utf8(out.stdout).unwrap().contains("no record"));

    std::fs::remove_dir_all(&dir).ok();
}
