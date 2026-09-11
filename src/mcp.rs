//! The tool boundary. `witness mcp -- <server> [args...]` sits between an MCP
//! client and a stdio MCP server, forwarding newline-delimited JSON-RPC in
//! both directions and recording `tools/call` exchanges into the same journal
//! and CAS the model proxy writes. One store then answers "what did my agents
//! do" across both boundaries, the model calls and the tool calls.
//!
//! Framing follows the MCP stdio transport, spec revision **2026-07-28**: one
//! JSON-RPC message per line, UTF-8, no embedded newlines, and the server's
//! stderr is a free-form log channel the client may forward untouched. That
//! framing has been identical in every published revision, so the wrapper also
//! works against servers speaking older ones; only the method names matter,
//! and `tools/call` has been spelled the same way throughout.
//!
//! The wrapper is deliberately not an MCP implementation. It never originates
//! a message, never rewrites one, and never waits on its own bookkeeping: it
//! reads a line, forwards it, and hands a copy to a recorder thread.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::cas::Cas;
use crate::journal::{InvokeEntry, Journal};

/// The MCP specification revision this wrapper was written against.
pub const SPEC_REVISION: &str = "2026-07-28";

/// The one method v1 records. Everything else is forwarded and counted.
pub const TOOLS_CALL: &str = "tools/call";

/// Journal `agent` for tool calls when `--agent` is not given. MCP has no
/// identity layer to read a Pact key from, so the boundary itself is the
/// identity until the client can present one.
pub const DEFAULT_AGENT: &str = "mcp-client";

/// Most JSON-RPC frames are small; tool results are the exception.
const LINE_HINT: usize = 8 * 1024;

pub struct Options {
    pub data_dir: PathBuf,
    /// Journal `agent` recorded for every tool call in this session.
    pub agent: String,
    /// The MCP server to wrap: program followed by its arguments.
    pub command: Vec<String>,
}

/// Which side of the wrapper a frame came from. The MCP stdio transport is a
/// single shared channel in each direction, so this is the only routing
/// information a frame carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    /// Client to server: requests and notifications.
    ToServer,
    /// Server to client: responses and notifications.
    FromServer,
}

/// A JSON-RPC frame, classified only as far as recording needs.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// A `method` plus an `id` a reply will echo.
    Request { id: String, method: String },
    /// A `method` with no `id`: nothing will answer it.
    Notification { method: String },
    /// A reply echoing a request's `id`.
    Response { id: String, error: bool },
    /// Well-formed JSON that is not a frame we can classify: batch arrays,
    /// replies whose id is null because the request could not be parsed, or
    /// anything else a non-conformant server puts on the wire.
    Opaque,
}

/// A `tools/call` request seen on the wire, waiting for its response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCall {
    pub tool: String,
    /// CAS hash of the request frame.
    pub req_hash: String,
}

/// What the session did, reported to stderr on exit.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Tool calls written to the journal.
    pub recorded: u64,
    /// Frames forwarded without a record: initialize, tools/list, resources,
    /// prompts, notifications, and the replies to all of them.
    pub passthrough: u64,
    /// Lines that were not JSON. A conformant server never writes one.
    pub unparsable: u64,
    /// Exchanges whose recording failed. The session is never broken for it.
    pub failed: u64,
    /// Tool calls still waiting for a response when the session ended.
    pub unanswered: u64,
}

/// JSON-RPC ids may be strings or numbers, and the type is part of the
/// identity, so `"1"` and `1` must not collide in the correlation map.
pub fn id_key(id: &Value) -> Option<String> {
    match id {
        Value::String(s) => Some(format!("s:{s}")),
        Value::Number(n) => Some(format!("n:{n}")),
        _ => None,
    }
}

/// Classify one parsed frame. Pure, so the whole correlation rule is testable
/// without a process on either end.
pub fn classify(value: &Value) -> Frame {
    let Some(obj) = value.as_object() else {
        return Frame::Opaque;
    };
    let id = obj.get("id").and_then(id_key);
    match (obj.get("method").and_then(Value::as_str), id) {
        (Some(method), Some(id)) => Frame::Request {
            id,
            method: method.to_string(),
        },
        (Some(method), None) => Frame::Notification {
            method: method.to_string(),
        },
        (None, Some(id)) => Frame::Response {
            id,
            error: obj.contains_key("error"),
        },
        (None, None) => Frame::Opaque,
    }
}

/// Decide whether a client frame opens a recorded exchange, and if so return
/// the correlation id and the tool being called.
///
/// A `tools/call` sent without an id is not recordable: nothing will ever
/// arrive to close the exchange, so it is counted as pass-through instead.
pub fn record_target(value: &Value) -> Option<(String, String)> {
    let obj = value.as_object()?;
    if obj.get("method")?.as_str()? != TOOLS_CALL {
        return None;
    }
    let id = obj.get("id").and_then(id_key)?;
    let tool = obj.get("params")?.get("name")?.as_str()?.to_string();
    Some((id, tool))
}

/// `mcp:<argv0>`, argv0 reduced to its file name so the journal stays readable
/// when a server is launched by absolute path.
pub fn upstream_label(program: &str) -> String {
    let name = Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(program);
    format!("mcp:{name}")
}

/// The journal `path` for a tool call. Namespaced so one `witness audit` can
/// tell a model call from a tool call by prefix alone.
pub fn journal_path(tool: &str) -> String {
    format!("mcp:{TOOLS_CALL}:{tool}")
}

/// Map a completed tool exchange onto the journal's invoke shape.
///
/// The model boundary and the tool boundary share one record type on purpose.
/// `model` is None because a tool call has no model; `cache` is always "miss"
/// because v1 never replays a tool call, only records it; `status` follows the
/// JSON-RPC envelope, so a tool that fails on its own terms (a result carrying
/// `isError: true`) is a successful exchange and stays 200.
pub fn build_entry(
    agent: &str,
    upstream: &str,
    call: &PendingCall,
    resp_hash: &str,
    error: bool,
) -> InvokeEntry {
    InvokeEntry {
        agent: agent.to_string(),
        root: None,
        req: call.req_hash.clone(),
        resp: resp_hash.to_string(),
        path: journal_path(&call.tool),
        model: None,
        upstream: upstream.to_string(),
        cache: "miss".into(),
        status: if error { 500 } else { 200 },
        sig: None,
    }
}

/// The frame bytes without their line terminator, so the CAS holds exactly the
/// JSON-RPC message the two ends exchanged.
fn frame_bytes(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

/// Work handed to the recorder thread. Never carries a parsed value: parsing
/// is the recorder's job, so the piping loops do no JSON work at all.
enum Msg {
    Line(Direction, Vec<u8>),
    Done,
}

struct Recorder {
    cas: Cas,
    journal: Journal,
    agent: String,
    upstream: String,
    pending: HashMap<String, PendingCall>,
    stats: Stats,
}

impl Recorder {
    fn observe(&mut self, dir: Direction, line: &[u8]) -> Result<()> {
        let body = frame_bytes(line);
        if body.is_empty() {
            return Ok(());
        }
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            self.stats.unparsable += 1;
            return Ok(());
        };
        match dir {
            Direction::ToServer => match record_target(&value) {
                Some((id, tool)) => {
                    let req_hash = self.cas.put(body).context("storing tool request")?;
                    self.pending.insert(id, PendingCall { tool, req_hash });
                }
                None => self.stats.passthrough += 1,
            },
            Direction::FromServer => {
                let matched = match classify(&value) {
                    Frame::Response { id, error } => {
                        self.pending.remove(&id).map(|call| (call, error))
                    }
                    _ => None,
                };
                match matched {
                    Some((call, error)) => {
                        let resp_hash = self.cas.put(body).context("storing tool response")?;
                        self.journal
                            .append_invoke(build_entry(
                                &self.agent,
                                &self.upstream,
                                &call,
                                &resp_hash,
                                error,
                            ))
                            .context("appending tool call to journal")?;
                        self.stats.recorded += 1;
                    }
                    None => self.stats.passthrough += 1,
                }
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Stats {
        self.stats.unanswered = self.pending.len() as u64;
        self.stats
    }
}

/// Drain the channel on a blocking thread. Every CAS and journal write in the
/// session happens here, never on a thread that a message is waiting on.
fn record_loop(rx: mpsc::Receiver<Msg>, mut rec: Recorder) -> Stats {
    while let Ok(Msg::Line(dir, line)) = rx.recv() {
        if let Err(e) = rec.observe(dir, &line) {
            // A full disk must not break someone's tool session. Say so
            // loudly on stderr and keep piping.
            eprintln!("witness mcp: recording failed: {e:#}");
            rec.stats.failed += 1;
        }
    }
    rec.finish()
}

/// Move lines from `src` to `dst` one at a time, copying each to the recorder.
/// Nothing is ever buffered beyond the line in flight.
async fn pump<R, W>(src: R, mut dst: W, dir: Direction, tx: mpsc::Sender<Msg>) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut src = BufReader::new(src);
    let mut line = Vec::with_capacity(LINE_HINT);
    loop {
        line.clear();
        if src.read_until(b'\n', &mut line).await? == 0 {
            break;
        }
        if dir == Direction::ToServer {
            // Enqueue before forwarding. A channel push is a memcpy and no
            // syscall, so it costs the client nothing, and it guarantees the
            // recorder sees a tools/call before the reply it must be matched
            // against. The CAS and journal writes still happen strictly after
            // the forward, on the recorder thread.
            let _ = tx.send(Msg::Line(dir, line.clone()));
            dst.write_all(&line).await?;
            dst.flush().await?;
        } else {
            // Forward first: nothing downstream is waiting on the record.
            dst.write_all(&line).await?;
            dst.flush().await?;
            let _ = tx.send(Msg::Line(dir, line.clone()));
        }
    }
    // EOF upstream. Closing the server's stdin is the spec's graceful
    // shutdown signal, and a conformant server exits on it.
    dst.shutdown().await.ok();
    Ok(())
}

/// Run the wrapper to completion. Returns the server's exit code so the MCP
/// client sees the process it thinks it launched.
pub async fn run(opts: Options) -> Result<i32> {
    let (program, args) = opts
        .command
        .split_first()
        .context("no MCP server command given (use: witness mcp -- <server> [args...])")?;

    // Fail before spawning anything if the store is not writable.
    let cas = Cas::open(&opts.data_dir).context("opening CAS")?;
    let journal = Journal::open(&opts.data_dir).context("opening journal")?;
    let upstream = upstream_label(program);

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // The server's stderr is its own log channel and carries no MCP
        // messages, so it passes through untouched.
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning MCP server '{program}'"))?;

    let child_stdin = child.stdin.take().expect("stdin was piped");
    let child_stdout = child.stdout.take().expect("stdout was piped");

    let (tx, rx) = mpsc::channel::<Msg>();
    let recorder = tokio::task::spawn_blocking({
        let rec = Recorder {
            cas,
            journal,
            agent: opts.agent,
            upstream,
            pending: HashMap::new(),
            stats: Stats::default(),
        };
        move || record_loop(rx, rec)
    });

    let to_server = tokio::spawn(pump(
        tokio::io::stdin(),
        child_stdin,
        Direction::ToServer,
        tx.clone(),
    ));
    let from_server = tokio::spawn(pump(
        child_stdout,
        tokio::io::stdout(),
        Direction::FromServer,
        tx.clone(),
    ));

    // The session ends when the server stops writing and exits.
    let _ = from_server.await;
    let status = child.wait().await.context("waiting for MCP server")?;

    // The client-side pump is probably parked in a read on our stdin that
    // nothing will complete, so close the recorder explicitly rather than
    // waiting for a sender that will never be dropped.
    to_server.abort();
    let _ = tx.send(Msg::Done);
    let stats = recorder.await.context("recorder thread panicked")?;

    eprintln!(
        "witness mcp: {} tool call(s) recorded, {} other message(s) passed through unrecorded",
        stats.recorded, stats.passthrough
    );
    if stats.unanswered > 0 {
        eprintln!(
            "witness mcp: {} tool call(s) had no response and were not recorded",
            stats.unanswered
        );
    }
    if stats.unparsable > 0 {
        eprintln!("witness mcp: {} line(s) were not JSON", stats.unparsable);
    }
    if stats.failed > 0 {
        eprintln!("witness mcp: {} exchange(s) failed to record", stats.failed);
    }
    if stats.recorded > 0 {
        eprintln!(
            "witness mcp: journal {} (`witness verify` checks the chain)",
            opts.data_dir.join("journal.log").display()
        );
    }
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ids_of_different_types_never_collide() {
        assert_ne!(id_key(&json!(1)), id_key(&json!("1")));
        assert_eq!(id_key(&json!(7)), id_key(&json!(7)));
        assert_eq!(id_key(&json!("abc")), id_key(&json!("abc")));
        // A null id cannot correlate an exchange.
        assert_eq!(id_key(&Value::Null), None);
    }

    #[test]
    fn classify_separates_the_four_frame_shapes() {
        assert_eq!(
            classify(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call"})),
            Frame::Request {
                id: "n:1".into(),
                method: TOOLS_CALL.into()
            }
        );
        assert_eq!(
            classify(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})),
            Frame::Notification {
                method: "notifications/initialized".into()
            }
        );
        assert_eq!(
            classify(&json!({"jsonrpc":"2.0","id":"a","result":{}})),
            Frame::Response {
                id: "s:a".into(),
                error: false
            }
        );
        assert_eq!(
            classify(&json!({"jsonrpc":"2.0","id":"a","error":{"code":-32601}})),
            Frame::Response {
                id: "s:a".into(),
                error: true
            }
        );
        // Batch arrays and null-id replies are forwarded, not classified.
        assert_eq!(classify(&json!([{"id":1,"result":{}}])), Frame::Opaque);
        assert_eq!(
            classify(&json!({"jsonrpc":"2.0","id":null,"error":{}})),
            Frame::Opaque
        );
    }

    #[test]
    fn only_identified_tool_calls_are_recorded() {
        let call = json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}
        });
        assert_eq!(
            record_target(&call),
            Some(("n:3".into(), "read_file".into()))
        );

        // Every other method passes through in v1.
        for method in [
            "initialize",
            "tools/list",
            "resources/read",
            "prompts/get",
            "notifications/cancelled",
        ] {
            let v = json!({"jsonrpc":"2.0","id":1,"method":method,"params":{"name":"x"}});
            assert_eq!(record_target(&v), None, "{method} must not be recorded");
        }

        // Unrecordable tools/call shapes: no id to match a response against,
        // and no tool name to attribute the call to.
        assert_eq!(
            record_target(&json!({"method":"tools/call","params":{"name":"x"}})),
            None
        );
        assert_eq!(
            record_target(&json!({"id":1,"method":"tools/call","params":{}})),
            None
        );
        assert_eq!(record_target(&json!({"id":1,"method":"tools/call"})), None);
    }

    #[test]
    fn entry_maps_onto_the_existing_invoke_shape() {
        let call = PendingCall {
            tool: "search_web".into(),
            req_hash: "aa".repeat(32),
        };
        let ok = build_entry(
            "mcp-client",
            "mcp:everything",
            &call,
            &"bb".repeat(32),
            false,
        );
        assert_eq!(ok.agent, "mcp-client");
        assert_eq!(ok.path, "mcp:tools/call:search_web");
        assert_eq!(ok.upstream, "mcp:everything");
        assert_eq!(ok.cache, "miss");
        assert_eq!(ok.status, 200);
        assert_eq!(ok.model, None);
        assert_eq!(ok.root, None);
        assert_eq!(ok.sig, None);
        assert_eq!(ok.req, "aa".repeat(32));
        assert_eq!(ok.resp, "bb".repeat(32));

        // A JSON-RPC error envelope is the only thing that makes it a 500.
        let failed = build_entry("a", "mcp:s", &call, &"cc".repeat(32), true);
        assert_eq!(failed.status, 500);
    }

    #[test]
    fn upstream_label_is_the_program_name() {
        assert_eq!(upstream_label("python3"), "mcp:python3");
        assert_eq!(
            upstream_label("/usr/local/bin/mcp-server-git"),
            "mcp:mcp-server-git"
        );
        assert_eq!(upstream_label("./server.js"), "mcp:server.js");
    }

    #[test]
    fn cas_bodies_exclude_the_line_terminator() {
        assert_eq!(frame_bytes(b"{\"a\":1}\n"), b"{\"a\":1}");
        assert_eq!(frame_bytes(b"{\"a\":1}\r\n"), b"{\"a\":1}");
        assert_eq!(frame_bytes(b"{\"a\":1}"), b"{\"a\":1}");
        assert_eq!(frame_bytes(b"\n"), b"");
    }

    /// The correlation rule end to end, with no process on either end: an
    /// interleaved session yields exactly the tool-call records.
    #[test]
    fn recorder_records_only_matched_tool_calls() {
        let dir = std::env::temp_dir().join(format!("witness-mcp-unit-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let mut rec = Recorder {
            cas: Cas::open(&dir).unwrap(),
            journal: Journal::open(&dir).unwrap(),
            agent: DEFAULT_AGENT.into(),
            upstream: "mcp:fake".into(),
            pending: HashMap::new(),
            stats: Stats::default(),
        };

        let session: &[(Direction, &str)] = &[
            (
                Direction::ToServer,
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
            ),
            (
                Direction::FromServer,
                r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            ),
            (
                Direction::ToServer,
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            ),
            (
                Direction::ToServer,
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            ),
            (
                Direction::FromServer,
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#,
            ),
            // Two tool calls in flight at once, answered out of order.
            (
                Direction::ToServer,
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"alpha"}}"#,
            ),
            (
                Direction::ToServer,
                r#"{"jsonrpc":"2.0","id":"4","method":"tools/call","params":{"name":"beta"}}"#,
            ),
            (
                Direction::FromServer,
                r#"{"jsonrpc":"2.0","id":"4","error":{"code":-32000,"message":"no"}}"#,
            ),
            (
                Direction::FromServer,
                r#"{"jsonrpc":"2.0","id":3,"result":{"content":[]}}"#,
            ),
            // A stray reply to a request we never saw, and a non-JSON line.
            (
                Direction::FromServer,
                r#"{"jsonrpc":"2.0","id":99,"result":{}}"#,
            ),
            (Direction::FromServer, "server chatter on the wrong stream"),
            // A tool call left hanging when the session ends.
            (
                Direction::ToServer,
                r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"gamma"}}"#,
            ),
        ];
        for (dir, line) in session {
            rec.observe(*dir, format!("{line}\n").as_bytes()).unwrap();
        }

        let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
        assert_eq!(Journal::verify_chain(&records).unwrap(), 2);
        // Journal order follows response order, not request order.
        assert_eq!(records[0].path, "mcp:tools/call:beta");
        assert_eq!(records[0].status, 500);
        assert_eq!(records[1].path, "mcp:tools/call:alpha");
        assert_eq!(records[1].status, 200);

        let stats = rec.finish();
        assert_eq!(stats.recorded, 2);
        assert_eq!(stats.unparsable, 1);
        assert_eq!(stats.unanswered, 1, "gamma never got a response");
        assert_eq!(stats.failed, 0);
        // initialize, its reply, initialized, tools/list, its reply, stray 99.
        assert_eq!(stats.passthrough, 6);

        std::fs::remove_dir_all(&dir).ok();
    }
}
