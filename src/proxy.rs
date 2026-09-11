//! The proxy core: an API-compatible sidecar between agents and a model API.
//! Every call is content-hashed, recorded in the CAS + journal, optionally
//! served from cache, and (when Pact headers are present) identity-verified
//! and capability-enforced at the network boundary.

use anyhow::{Context, Result};
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio_stream::wrappers::ReceiverStream;

use crate::cas::Cas;
use crate::hash::request_key;
use crate::identity::{
    caps_allow_model, chain_from_b64, verify_chain, verify_request_signature, HDR_DELEGATION,
    HDR_IDENTITY, HDR_SIGNATURE, HDR_TIMESTAMP,
};
use crate::journal::{now_ms, InvokeEntry, Journal};
use crate::metrics::Metrics;
use crate::otlp::{self, Exporter, SpanData};

const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Allow a caller to opt a nondeterministic request into cache reuse.
pub const HDR_CACHE_OPT_IN: &str = "x-witness-cache";
/// Local introspection. Never proxied, never recorded, never journaled.
pub const METRICS_PATH: &str = "/witness/metrics";

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    /// Record identity when offered; anonymous calls pass through.
    Open,
    /// Every call must carry a valid delegation chain from a trusted root.
    Required,
}

pub struct Options {
    pub port: u16,
    pub upstream: String,
    pub data_dir: PathBuf,
    pub mode: Mode,
    /// Trusted root pubkeys (hex). Empty in Required mode = any valid chain.
    pub trust: Vec<String>,
    pub cache: bool,
    /// Replay mode: never contact the upstream; cache misses are errors.
    pub replay: bool,
    /// OTLP/HTTP collector to project recorded calls onto as GenAI spans.
    /// `None` disables the exporter entirely, including its background task.
    pub otlp_endpoint: Option<String>,
}

/// Cache index entry: maps a request key to the stored response.
#[derive(Serialize, Deserialize)]
struct CacheEntry {
    resp_hash: String,
    status: u16,
    content_type: String,
    streamed: bool,
}

pub struct App {
    cas: Cas,
    journal: Journal,
    client: reqwest::Client,
    opts: Options,
    cache_dir: PathBuf,
    metrics: Arc<Metrics>,
    otlp: Option<Exporter>,
    /// Resolved once from the upstream URL; every span carries it.
    gen_ai_system: &'static str,
    tmp_counter: AtomicU64,
}

impl App {
    /// Project one recorded call onto a GenAI span. No-op without `--otlp-endpoint`.
    #[allow(clippy::too_many_arguments)]
    fn emit_span(
        &self,
        start_unix_nanos: u64,
        seq: u64,
        cache: &str,
        req_hash: &str,
        resp_hash: &str,
        agent: &str,
        model: &Option<String>,
        status: u16,
    ) {
        let Some(exporter) = &self.otlp else {
            return;
        };
        exporter.emit(
            SpanData {
                seq,
                model: model.clone(),
                cache: cache.to_string(),
                req_hash: req_hash.to_string(),
                resp_hash: resp_hash.to_string(),
                agent: agent.to_string(),
                system: self.gen_ai_system,
                start_unix_nanos,
                end_unix_nanos: otlp::now_unix_nanos(),
                status,
            },
            &self.metrics,
        );
    }

    fn cache_path(&self, req_key: &str) -> PathBuf {
        self.cache_dir.join(req_key)
    }

    fn cache_get(&self, req_key: &str) -> Option<CacheEntry> {
        let data = std::fs::read(self.cache_path(req_key)).ok()?;
        serde_json::from_slice(&data).ok()
    }

    fn cache_put(&self, req_key: &str, entry: &CacheEntry) -> Result<()> {
        // Atomic publish: concurrent writers of the same key must never leave
        // a torn index file behind, which would silently disable caching.
        let path = self.cache_path(req_key);
        // The first recorded response for a key is the canonical one, so this
        // is write-once. Skipping the rewrite keeps repeat traffic off the
        // filesystem entirely — the hot path for any real fleet.
        if path.exists() {
            return Ok(());
        }
        let tmp = path.with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            self.tmp_counter.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&tmp, serde_json::to_vec(entry)?)?;
        if let Err(e) = std::fs::rename(&tmp, &path) {
            std::fs::remove_file(&tmp).ok();
            return Err(e.into());
        }
        Ok(())
    }
}

pub async fn serve(opts: Options) -> Result<()> {
    let cas = Cas::open(&opts.data_dir)?;
    let journal = Journal::open(&opts.data_dir)?;
    let cache_dir = opts.data_dir.join("cache");
    std::fs::create_dir_all(&cache_dir)?;
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()?;
    let port = opts.port;
    let replay = opts.replay;
    let metrics = Arc::new(Metrics::default());
    let gen_ai_system = otlp::gen_ai_system(&opts.upstream);
    let otlp = opts
        .otlp_endpoint
        .as_deref()
        .map(|endpoint| Exporter::spawn(endpoint, client.clone(), metrics.clone()));
    if let Some(endpoint) = &opts.otlp_endpoint {
        eprintln!(
            "witness: OTLP GenAI spans to {}",
            otlp::traces_url(endpoint)
        );
    }
    let app = Arc::new(App {
        cas,
        journal,
        client,
        opts,
        cache_dir,
        metrics,
        otlp,
        gen_ai_system,
        tmp_counter: AtomicU64::new(0),
    });

    let router = Router::new()
        .route(METRICS_PATH, get(metrics_endpoint))
        .fallback(handle)
        .with_state(app);

    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    eprintln!(
        "witness {} on http://{addr}  (journal + CAS recording every call, metrics at {METRICS_PATH})",
        if replay { "REPLAY" } else { "serving" }
    );
    axum::serve(listener, router).await?;
    Ok(())
}

struct Caller {
    agent: String,
    root: Option<String>,
    caps: Option<Vec<String>>,
    sig: Option<String>,
}

fn anonymous() -> Caller {
    Caller {
        agent: "anonymous".into(),
        root: None,
        caps: None,
        sig: None,
    }
}

/// Verify Pact headers if present; enforce policy per mode.
fn authenticate(
    app: &App,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Caller, (StatusCode, String)> {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let identity = get(HDR_IDENTITY);

    if identity.is_none() {
        if app.opts.mode == Mode::Required {
            return Err((
                StatusCode::UNAUTHORIZED,
                "this proxy requires Pact identity headers (x-pact-identity, x-pact-timestamp, x-pact-signature, x-pact-delegation)".into(),
            ));
        }
        return Ok(anonymous());
    }

    let identity = identity.unwrap().to_string();
    let ts: u64 = get(HDR_TIMESTAMP).and_then(|v| v.parse().ok()).ok_or((
        StatusCode::UNAUTHORIZED,
        "missing or invalid x-pact-timestamp".into(),
    ))?;
    let sig = get(HDR_SIGNATURE)
        .ok_or((StatusCode::UNAUTHORIZED, "missing x-pact-signature".into()))?
        .to_string();

    verify_request_signature(&identity, &sig, method.as_str(), path, ts, body, now_ms()).map_err(
        |e| {
            (
                StatusCode::UNAUTHORIZED,
                format!("request signature rejected: {e:#}"),
            )
        },
    )?;

    match get(HDR_DELEGATION) {
        Some(encoded) => {
            let chain = chain_from_b64(encoded).map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    format!("bad delegation chain: {e:#}"),
                )
            })?;
            let verified = verify_chain(&chain, now_ms()).map_err(|e| {
                (
                    StatusCode::FORBIDDEN,
                    format!("delegation chain rejected: {e:#}"),
                )
            })?;
            if verified.agent != identity {
                return Err((
                    StatusCode::FORBIDDEN,
                    "request signer is not the delegation chain's final subject".into(),
                ));
            }
            if !app.opts.trust.is_empty() && !app.opts.trust.contains(&verified.root) {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!("chain root {} is not a trusted root", verified.root),
                ));
            }
            Ok(Caller {
                agent: verified.agent,
                root: Some(verified.root),
                caps: Some(verified.capabilities),
                sig: Some(sig),
            })
        }
        None => {
            if app.opts.mode == Mode::Required {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "x-pact-delegation chain required in this mode".into(),
                ));
            }
            // Self-sovereign: signed, but acting under no one's grant.
            Ok(Caller {
                agent: identity,
                root: None,
                caps: None,
                sig: Some(sig),
            })
        }
    }
}

fn body_model(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .get("model")?
        .as_str()
        .map(String::from)
}

/// A request is safe to *reuse* from cache only when it's deterministic
/// (temperature 0 or an explicit seed) or the caller opts in. Everything is
/// *recorded* regardless — replay always works.
fn reusable(body: &[u8], headers: &HeaderMap) -> bool {
    if headers
        .get(HDR_CACHE_OPT_IN)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("allow"))
        .unwrap_or(false)
    {
        return true;
    }
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    if v.get("seed").is_some() {
        return true;
    }
    v.get("temperature").and_then(Value::as_f64) == Some(0.0)
}

fn json_error(status: StatusCode, msg: &str) -> Response {
    let body = serde_json::json!({"type": "error", "error": {"type": "witness_proxy_error", "message": msg}});
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn witness_headers(resp: &mut Response, seq: u64, req_key: &str, resp_hash: &str, cache: &str) {
    let h = resp.headers_mut();
    h.insert(
        "x-witness-seq",
        HeaderValue::from_str(&seq.to_string()).unwrap(),
    );
    h.insert("x-witness-req", HeaderValue::from_str(req_key).unwrap());
    h.insert("x-witness-resp", HeaderValue::from_str(resp_hash).unwrap());
    h.insert("x-witness-cache", HeaderValue::from_str(cache).unwrap());
}

/// Local introspection endpoint. It is a route rather than a branch inside
/// `handle` so the path can never reach the recording or forwarding path.
async fn metrics_endpoint(State(app): State<Arc<App>>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(app.metrics.render(app.journal.len())))
        .unwrap()
}

async fn handle(State(app): State<Arc<App>>, req: Request) -> Response {
    let started = Instant::now();
    let response = proxy_request(&app, req).await;
    app.metrics.observe(started.elapsed());
    response
}

async fn proxy_request(app: &Arc<App>, req: Request) -> Response {
    let start_unix_nanos = otlp::now_unix_nanos();
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let headers = req.headers().clone();

    let body = match axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return json_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };

    let caller = match authenticate(app, &method, &path, &headers, &body) {
        Ok(c) => c,
        Err((status, msg)) => return json_error(status, &msg),
    };
    if caller.sig.is_some() {
        app.metrics.signed.fetch_add(1, Ordering::Relaxed);
    }

    let model = body_model(&body);

    // Capability enforcement: a presented grant is binding even in open mode.
    if let (Some(caps), Some(m)) = (&caller.caps, &model) {
        if !caps_allow_model(caps, m) {
            return json_error(
                StatusCode::FORBIDDEN,
                &format!("delegation chain does not grant model:{m}"),
            );
        }
    }

    // Two hashes per request: the cache key (method+path+canonical body,
    // whitespace/key-order independent) and the CAS hash of the raw body,
    // which is what the journal references so audits can load it.
    let req_key = request_key(method.as_str(), &path, &body);
    let body_hash = match app.cas.put(&body) {
        Ok(h) => h,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("CAS write failed: {e:#}"),
            )
        }
    };

    // --- cache / replay path ---
    let cached = app.cache_get(&req_key);
    let serve_cached = match (&cached, app.opts.replay, app.opts.cache) {
        (Some(_), true, _) => true,
        (Some(_), false, true) => reusable(&body, &headers),
        _ => false,
    };

    if app.opts.replay && cached.is_none() {
        return json_error(
            StatusCode::CONFLICT,
            "replay mode: no recorded response for this request",
        );
    }

    if serve_cached {
        let entry = cached.unwrap();
        let bytes = match app.cas.get(&entry.resp_hash) {
            Ok(Some(b)) => b,
            _ => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "cache index points at missing object",
                )
            }
        };
        let cache_kind = if app.opts.replay { "replay" } else { "hit" };
        if app.opts.replay {
            app.metrics.replays.fetch_add(1, Ordering::Relaxed);
        } else {
            app.metrics.hits.fetch_add(1, Ordering::Relaxed);
        }
        let agent = caller.agent.clone();
        let record = app.journal.append_invoke(InvokeEntry {
            agent: caller.agent,
            root: caller.root,
            req: body_hash.clone(),
            resp: entry.resp_hash.clone(),
            path: path.clone(),
            model: model.clone(),
            upstream: "cache".into(),
            cache: cache_kind.into(),
            status: entry.status,
            sig: caller.sig,
        });
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("journal write failed: {e:#}"),
                )
            }
        };
        let mut resp = Response::builder()
            .status(entry.status)
            .header("content-type", entry.content_type)
            .body(Body::from(bytes))
            .unwrap();
        witness_headers(
            &mut resp,
            record.seq,
            &body_hash,
            &entry.resp_hash,
            cache_kind,
        );
        app.emit_span(
            start_unix_nanos,
            record.seq,
            cache_kind,
            &body_hash,
            &entry.resp_hash,
            &agent,
            &model,
            entry.status,
        );
        return resp;
    }

    // --- forward upstream ---
    app.metrics.misses.fetch_add(1, Ordering::Relaxed);
    let url = format!("{}{}", app.opts.upstream.trim_end_matches('/'), path);
    let mut upstream_req = app.client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
        &url,
    );
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if n == "host"
            || n == "content-length"
            || n.starts_with("x-pact-")
            || n.starts_with("x-witness-")
        {
            continue;
        }
        upstream_req = upstream_req.header(name, value);
    }
    let upstream_resp = match upstream_req.body(body.to_vec()).send().await {
        Ok(r) => r,
        Err(e) => {
            app.metrics.upstream_errors.fetch_add(1, Ordering::Relaxed);
            return json_error(
                StatusCode::BAD_GATEWAY,
                &format!("upstream unreachable: {e}"),
            );
        }
    };

    let status = upstream_resp.status().as_u16();
    let content_type = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let is_stream = content_type.starts_with("text/event-stream");
    let upstream_host = app.opts.upstream.clone();

    if !is_stream {
        let bytes = match upstream_resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                app.metrics.upstream_errors.fetch_add(1, Ordering::Relaxed);
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream read failed: {e}"),
                );
            }
        };
        let (seq, resp_hash) = match record_response(
            app,
            &caller,
            &req_key,
            &body_hash,
            &path,
            &model,
            &upstream_host,
            status,
            &content_type,
            &bytes,
            true,
            start_unix_nanos,
        ) {
            Ok(v) => v,
            Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
        };
        let mut resp = Response::builder()
            .status(status)
            .header("content-type", content_type)
            .body(Body::from(bytes))
            .unwrap();
        witness_headers(&mut resp, seq, &body_hash, &resp_hash, "miss");
        return resp;
    }

    // --- streaming tee: forward chunks live, record the full body at the end ---
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    let app2 = app.clone();
    let req_key2 = req_key.clone();
    let body_hash2 = body_hash.clone();
    let path2 = path.clone();
    let ct2 = content_type.clone();
    tokio::spawn(async move {
        let mut collected: Vec<u8> = Vec::new();
        let mut stream = upstream_resp.bytes_stream();
        let mut failed = false;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    collected.extend_from_slice(&bytes);
                    if tx.send(Ok(bytes)).await.is_err() {
                        // Client went away; keep collecting so the record is complete.
                    }
                }
                Err(e) => {
                    failed = true;
                    app2.metrics.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    break;
                }
            }
        }
        // Only a completed stream becomes a reusable cache entry.
        if let Err(e) = record_response(
            &app2,
            &caller,
            &req_key2,
            &body_hash2,
            &path2,
            &model,
            &upstream_host,
            status,
            &ct2,
            &collected,
            !failed,
            start_unix_nanos,
        ) {
            eprintln!("witness: failed to record streamed response: {e:#}");
        }
    });

    let mut resp = Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Body::from_stream(ReceiverStream::new(rx)))
        .unwrap();
    resp.headers_mut()
        .insert("x-witness-req", HeaderValue::from_str(&body_hash).unwrap());
    resp.headers_mut()
        .insert("x-witness-cache", HeaderValue::from_static("miss"));
    resp
}

#[allow(clippy::too_many_arguments)]
fn record_response(
    app: &App,
    caller: &Caller,
    req_key: &str,
    body_hash: &str,
    path: &str,
    model: &Option<String>,
    upstream: &str,
    status: u16,
    content_type: &str,
    bytes: &[u8],
    cacheable: bool,
    start_unix_nanos: u64,
) -> Result<(u64, String)> {
    let resp_hash = app.cas.put(bytes)?;
    if status < 400 && cacheable {
        app.cache_put(
            req_key,
            &CacheEntry {
                resp_hash: resp_hash.clone(),
                status,
                content_type: content_type.to_string(),
                streamed: content_type.starts_with("text/event-stream"),
            },
        )?;
    }
    let record = app.journal.append_invoke(InvokeEntry {
        agent: caller.agent.clone(),
        root: caller.root.clone(),
        req: body_hash.to_string(),
        resp: resp_hash.clone(),
        path: path.to_string(),
        model: model.clone(),
        upstream: upstream.to_string(),
        cache: "miss".into(),
        status,
        sig: caller.sig.clone(),
    })?;
    app.emit_span(
        start_unix_nanos,
        record.seq,
        "miss",
        body_hash,
        &resp_hash,
        &caller.agent,
        model,
        status,
    );
    Ok((record.seq, resp_hash))
}
