//! A minimal OpenTelemetry projection: every recorded call is also published
//! as a GenAI span over OTLP/HTTP with a JSON body we build by hand.
//!
//! This is deliberately not the `opentelemetry` crate stack. Witness already
//! has the authoritative record in the journal; the span is a convenience
//! export for an existing tracing backend, so it is worth ~200 lines and zero
//! new dependencies, not a protobuf toolchain. There is no context
//! propagation, no sampling, and no retry: every span is its own root trace,
//! and spans are dropped rather than allowed to slow the request path.

use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::metrics::Metrics;

/// Bounded so a stalled collector costs memory in a fixed amount, not
/// unboundedly. Overflow is counted and dropped, never awaited.
const QUEUE_DEPTH: usize = 1024;
/// Spans per OTLP request. One export per drained batch keeps the collector's
/// request rate well below the proxy's.
const MAX_BATCH: usize = 64;

/// One recorded call, flattened into what the span needs.
pub struct SpanData {
    pub seq: u64,
    pub model: Option<String>,
    pub cache: String,
    pub req_hash: String,
    pub resp_hash: String,
    pub agent: String,
    pub system: &'static str,
    pub start_unix_nanos: u64,
    pub end_unix_nanos: u64,
    pub status: u16,
}

pub struct Exporter {
    tx: tokio::sync::mpsc::Sender<SpanData>,
}

impl Exporter {
    /// Spawn the single sender task. Returns immediately; the caller's request
    /// path only ever does a non-blocking `try_send`.
    pub fn spawn(endpoint: &str, client: reqwest::Client, metrics: Arc<Metrics>) -> Self {
        let url = traces_url(endpoint);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SpanData>(QUEUE_DEPTH);
        tokio::spawn(async move {
            while let Some(first) = rx.recv().await {
                let mut batch = vec![first];
                while batch.len() < MAX_BATCH {
                    match rx.try_recv() {
                        Ok(next) => batch.push(next),
                        Err(_) => break,
                    }
                }
                let n = batch.len() as u64;
                let body = request_body(&batch).to_string();
                let sent = client
                    .post(&url)
                    .header("content-type", "application/json")
                    .body(body)
                    .send()
                    .await;
                let accepted = match sent {
                    Ok(resp) if resp.status().is_success() => true,
                    Ok(resp) => {
                        eprintln!("witness: OTLP endpoint returned {}", resp.status());
                        false
                    }
                    Err(e) => {
                        eprintln!("witness: OTLP export failed: {e}");
                        false
                    }
                };
                let counter = if accepted {
                    &metrics.otlp_exported
                } else {
                    &metrics.otlp_dropped
                };
                counter.fetch_add(n, Ordering::Relaxed);
            }
        });
        Self { tx }
    }

    /// Fire and forget. A full queue means telemetry is behind the proxy, and
    /// the proxy always wins.
    pub fn emit(&self, span: SpanData, metrics: &Metrics) {
        if self.tx.try_send(span).is_err() {
            metrics.otlp_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn now_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// OTLP/HTTP wants the signal-specific path. Accept either the collector base
/// URL (the common `http://host:4318`) or a full traces URL.
pub fn traces_url(endpoint: &str) -> String {
    let trimmed = endpoint.trim_end_matches('/');
    if trimmed.ends_with("/v1/traces") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/v1/traces")
    }
}

/// `gen_ai.system` is an open enum; map the upstream we are fronting onto a
/// known value and fall back to the semconv's `_OTHER` rather than inventing
/// vendor names.
pub fn gen_ai_system(upstream: &str) -> &'static str {
    let u = upstream.to_ascii_lowercase();
    for (needle, system) in [
        ("anthropic", "anthropic"),
        ("openai", "openai"),
        ("azure", "az.ai.openai"),
        ("gemini", "gcp.gemini"),
        ("googleapis", "gcp.gemini"),
        ("bedrock", "aws.bedrock"),
        ("mistral", "mistral_ai"),
        ("cohere", "cohere"),
    ] {
        if u.contains(needle) {
            return system;
        }
    }
    "_OTHER"
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if getrandom::getrandom(&mut buf).is_err() {
        // Entropy is unavailable only in exotic sandboxes. A span with a
        // time-derived id is still a usable span; failing the call is not.
        let ns = now_unix_nanos().to_be_bytes();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ns[i % ns.len()] ^ (i as u8);
        }
    }
    hex::encode(buf)
}

fn attr(key: &str, value: Value) -> Value {
    json!({"key": key, "value": value})
}

fn string_attr(key: &str, value: &str) -> Value {
    attr(key, json!({"stringValue": value}))
}

fn span_json(s: &SpanData) -> Value {
    let model = s.model.as_deref();
    let name = match model {
        Some(m) => format!("chat {m}"),
        None => "chat".to_string(),
    };
    let mut attributes = vec![
        string_attr("gen_ai.system", s.system),
        string_attr("gen_ai.operation.name", "chat"),
        string_attr("witness.cache", &s.cache),
        string_attr("witness.req_hash", &s.req_hash),
        string_attr("witness.resp_hash", &s.resp_hash),
        string_attr("witness.agent", &s.agent),
        attr("witness.seq", json!({ "intValue": s.seq.to_string() })),
    ];
    if let Some(m) = model {
        attributes.push(string_attr("gen_ai.request.model", m));
    }
    json!({
        "traceId": random_hex(16),
        "spanId": random_hex(8),
        "name": name,
        // SPAN_KIND_CLIENT: witness stands in for the model API call.
        "kind": 3,
        "startTimeUnixNano": s.start_unix_nanos.to_string(),
        "endTimeUnixNano": s.end_unix_nanos.to_string(),
        "attributes": attributes,
        // STATUS_CODE_ERROR / STATUS_CODE_OK.
        "status": {"code": if s.status >= 400 { 2 } else { 1 }},
    })
}

/// One `ExportTraceServiceRequest` in the OTLP/JSON encoding. 64-bit fields
/// are strings and byte fields are hex, per the protobuf JSON mapping.
fn request_body(batch: &[SpanData]) -> Value {
    json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    string_attr("service.name", "witness"),
                    string_attr("service.version", env!("CARGO_PKG_VERSION")),
                ]
            },
            "scopeSpans": [{
                "scope": {"name": "witness", "version": env!("CARGO_PKG_VERSION")},
                "spans": batch.iter().map(span_json).collect::<Vec<_>>(),
            }]
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SpanData {
        SpanData {
            seq: 42,
            model: Some("claude-sonnet-5".into()),
            cache: "miss".into(),
            req_hash: "aa".repeat(32),
            resp_hash: "bb".repeat(32),
            agent: "anonymous".into(),
            system: "anthropic",
            start_unix_nanos: 1_000,
            end_unix_nanos: 2_000,
            status: 200,
        }
    }

    #[test]
    fn endpoint_accepts_base_or_full_url() {
        assert_eq!(traces_url("http://h:4318"), "http://h:4318/v1/traces");
        assert_eq!(traces_url("http://h:4318/"), "http://h:4318/v1/traces");
        assert_eq!(
            traces_url("http://h:4318/v1/traces"),
            "http://h:4318/v1/traces"
        );
    }

    #[test]
    fn body_follows_the_otlp_json_shape() {
        let body = request_body(&[sample()]);
        let span = &body["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["name"], "chat claude-sonnet-5");
        assert_eq!(span["kind"], 3);
        // 64-bit fields are strings, ids are hex of the right width.
        assert_eq!(span["startTimeUnixNano"], "1000");
        assert_eq!(span["traceId"].as_str().unwrap().len(), 32);
        assert_eq!(span["spanId"].as_str().unwrap().len(), 16);

        let attrs = span["attributes"].as_array().unwrap();
        let get = |k: &str| {
            attrs
                .iter()
                .find(|a| a["key"] == k)
                .unwrap_or_else(|| panic!("missing attribute {k}"))
                .clone()
        };
        assert_eq!(get("gen_ai.system")["value"]["stringValue"], "anthropic");
        assert_eq!(get("gen_ai.operation.name")["value"]["stringValue"], "chat");
        assert_eq!(
            get("gen_ai.request.model")["value"]["stringValue"],
            "claude-sonnet-5"
        );
        assert_eq!(get("witness.seq")["value"]["intValue"], "42");
        assert_eq!(get("witness.cache")["value"]["stringValue"], "miss");
    }

    #[test]
    fn unnamed_model_still_produces_a_valid_span() {
        let mut s = sample();
        s.model = None;
        s.status = 503;
        let body = request_body(&[s]);
        let span = &body["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["name"], "chat");
        assert_eq!(span["status"]["code"], 2);
        assert!(span["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["key"] != "gen_ai.request.model"));
    }

    #[test]
    fn system_maps_known_upstreams_and_falls_back() {
        assert_eq!(gen_ai_system("https://api.anthropic.com"), "anthropic");
        assert_eq!(gen_ai_system("https://api.openai.com/v1"), "openai");
        assert_eq!(gen_ai_system("http://127.0.0.1:9700"), "_OTHER");
    }

    #[test]
    fn trace_ids_are_unique_per_span() {
        let body = request_body(&[sample(), sample()]);
        let spans = body["resourceSpans"][0]["scopeSpans"][0]["spans"]
            .as_array()
            .unwrap()
            .clone();
        assert_ne!(spans[0]["traceId"], spans[1]["traceId"]);
    }
}
