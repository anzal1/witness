//! End-to-end: mock upstream + proxy in-process, exercising record → cache →
//! identity enforcement → replay → commit → prove.

use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

use witness::identity::{
    chain_to_b64, sign_request, Delegation, Keypair, HDR_DELEGATION, HDR_IDENTITY, HDR_SIGNATURE,
    HDR_TIMESTAMP,
};
use witness::journal::{now_ms, Journal};
use witness::{merkle, mock, proxy};

const MOCK_PORT: u16 = 39701;
const PROXY_PORT: u16 = 39702;
const REPLAY_PORT: u16 = 39703;

fn data_dir() -> PathBuf {
    std::env::temp_dir().join(format!("witness-e2e-{}", std::process::id()))
}

async fn wait_for(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server on port {port} never came up");
}

fn body(prompt: &str, model: &str) -> Value {
    json!({
        "model": model,
        "max_tokens": 64,
        "temperature": 0.0,
        "messages": [{"role": "user", "content": prompt}],
    })
}

async fn post(
    port: u16,
    body: &Value,
    extra_headers: Vec<(&str, String)>,
) -> (u16, Value, Option<String>) {
    let client = reqwest::Client::new();
    let mut req = client
        .post(format!("http://127.0.0.1:{port}/v1/messages"))
        .header("content-type", "application/json");
    for (name, value) in extra_headers {
        req = req.header(name, value);
    }
    let resp = req.body(body.to_string()).send().await.unwrap();
    let status = resp.status().as_u16();
    let cache = resp
        .headers()
        .get("x-witness-cache")
        .map(|v| v.to_str().unwrap().to_string());
    let text = resp.text().await.unwrap();
    let parsed = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, parsed, cache)
}

fn signed_headers(
    key: &Keypair,
    chain: Option<&[Delegation]>,
    body: &Value,
) -> Vec<(&'static str, String)> {
    let ts = now_ms();
    let body_bytes = body.to_string().into_bytes();
    let sig = sign_request(key, "POST", "/v1/messages", ts, &body_bytes);
    let mut headers = vec![
        (HDR_IDENTITY, key.public_hex()),
        (HDR_TIMESTAMP, ts.to_string()),
        (HDR_SIGNATURE, sig),
    ];
    if let Some(chain) = chain {
        headers.push((HDR_DELEGATION, chain_to_b64(chain).unwrap()));
    }
    headers
}

#[tokio::test(flavor = "multi_thread")]
async fn full_lifecycle() {
    let dir = data_dir();
    std::fs::remove_dir_all(&dir).ok();

    // Mock upstream with visible latency; recording proxy with cache on.
    tokio::spawn(mock::serve(MOCK_PORT, 300));
    let proxy_dir = dir.clone();
    tokio::spawn(async move {
        proxy::serve(proxy::Options {
            port: PROXY_PORT,
            upstream: format!("http://127.0.0.1:{MOCK_PORT}"),
            data_dir: proxy_dir,
            mode: proxy::Mode::Open,
            trust: Vec::new(),
            cache: true,
            replay: false,
            otlp_endpoint: None,
        })
        .await
        .unwrap();
    });
    wait_for(MOCK_PORT).await;
    wait_for(PROXY_PORT).await;

    // 1. First deterministic call: recorded, forwarded (miss).
    let b = body("prove lemma L1", "claude-sonnet-5");
    let (status, resp1, cache) = post(PROXY_PORT, &b, vec![]).await;
    assert_eq!(status, 200);
    assert_eq!(cache.as_deref(), Some("miss"));

    // 2. Identical call: served from cache, byte-identical.
    let (status, resp2, cache) = post(PROXY_PORT, &b, vec![]).await;
    assert_eq!(status, 200);
    assert_eq!(cache.as_deref(), Some("hit"));
    assert_eq!(resp1, resp2);

    // 3. Nondeterministic call (temperature 1) is recorded but NOT reused.
    let mut hot = body("prove lemma L1", "claude-sonnet-5");
    hot["temperature"] = json!(1.0);
    let (_, _, cache) = post(PROXY_PORT, &hot, vec![]).await;
    assert_eq!(cache.as_deref(), Some("miss"));
    let (_, _, cache) = post(PROXY_PORT, &hot, vec![]).await;
    assert_eq!(
        cache.as_deref(),
        Some("miss"),
        "hot request must not be reused"
    );

    // 4. Pact identity: human -> agent chain restricted to claude models.
    let human = Keypair::generate().unwrap();
    let agent = Keypair::generate().unwrap();
    let d = Delegation::issue(
        &human,
        &agent.public_hex(),
        vec!["model:claude-*".into()],
        600,
    )
    .unwrap();
    let chain = vec![d];

    let allowed = body("signed lemma L2", "claude-sonnet-5");
    let headers = signed_headers(&agent, Some(&chain), &allowed);
    let (status, _, _) = post(PROXY_PORT, &allowed, headers).await;
    assert_eq!(status, 200);

    // 5. Capability enforcement: model outside the grant is refused.
    let denied = body("signed lemma L2", "gpt-6-astra");
    let headers = signed_headers(&agent, Some(&chain), &denied);
    let (status, err, _) = post(PROXY_PORT, &denied, headers).await;
    assert_eq!(status, 403, "expected capability denial, got: {err}");

    // 6. Tampered body after signing is rejected.
    let signed = body("original", "claude-sonnet-5");
    let headers = signed_headers(&agent, Some(&chain), &signed);
    let tampered = body("tampered", "claude-sonnet-5");
    let (status, _, _) = post(PROXY_PORT, &tampered, headers).await;
    assert_eq!(status, 401);

    // 7. Journal chain verifies; signed calls carry agent identity; and the
    // journal's req hash resolves in the CAS to the actual body (audit path).
    let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
    Journal::verify_chain(&records).unwrap();
    assert!(records
        .iter()
        .any(|r| r.agent == agent.public_hex()
            && r.root.as_deref() == Some(human.public_hex().as_str())));
    let cas = witness::cas::Cas::open(&dir).unwrap();
    let auditable = records.iter().any(|r| {
        cas.get(&r.req)
            .ok()
            .flatten()
            .map(|obj| {
                obj.windows(b"prove lemma L1".len())
                    .any(|w| w == b"prove lemma L1")
            })
            .unwrap_or(false)
    });
    assert!(
        auditable,
        "journal req hashes must resolve to stored request bodies"
    );

    // 8. Replay: a second "run" served entirely from the record, no upstream.
    let replay_dir = dir.clone();
    tokio::spawn(async move {
        proxy::serve(proxy::Options {
            port: REPLAY_PORT,
            upstream: "replay://".into(),
            data_dir: replay_dir,
            mode: proxy::Mode::Open,
            trust: Vec::new(),
            cache: true,
            replay: true,
            otlp_endpoint: None,
        })
        .await
        .unwrap();
    });
    wait_for(REPLAY_PORT).await;
    let (status, replayed, cache) = post(REPLAY_PORT, &b, vec![]).await;
    assert_eq!(status, 200);
    assert_eq!(cache.as_deref(), Some("replay"));
    assert_eq!(replayed, resp1);

    // Unrecorded request in replay mode is a hard error, not a model call.
    let novel = body("never seen before", "claude-sonnet-5");
    let (status, _, _) = post(REPLAY_PORT, &novel, vec![]).await;
    assert_eq!(status, 409);

    // 9. Commit + inclusion proof round-trip.
    let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
    let leaves = Journal::leaf_hashes(&records);
    let root = merkle::root(&leaves).unwrap();
    let proof = merkle::prove(&leaves, 0).unwrap();
    assert_eq!(proof.root, hex::encode(root));
    assert!(merkle::verify(&proof));

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn required_mode_rejects_anonymous() {
    let dir = std::env::temp_dir().join(format!("witness-e2e-req-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let port = 39710;
    let human = Keypair::generate().unwrap();
    let trust = vec![human.public_hex()];
    let proxy_dir = dir.clone();
    tokio::spawn(async move {
        proxy::serve(proxy::Options {
            port,
            upstream: format!("http://127.0.0.1:{MOCK_PORT}"),
            data_dir: proxy_dir,
            mode: proxy::Mode::Required,
            trust,
            cache: false,
            replay: false,
            otlp_endpoint: None,
        })
        .await
        .unwrap();
    });
    wait_for(port).await;

    let b = body("anonymous attempt", "claude-sonnet-5");
    let (status, _, _) = post(port, &b, vec![]).await;
    assert_eq!(status, 401);

    // A chain from an untrusted root is refused even if internally valid.
    let mallory = Keypair::generate().unwrap();
    let agent = Keypair::generate().unwrap();
    let d = Delegation::issue(&mallory, &agent.public_hex(), vec!["model:*".into()], 600).unwrap();
    let headers = signed_headers(&agent, Some(&[d]), &b);
    let (status, _, _) = post(port, &b, headers).await;
    assert_eq!(status, 403);

    std::fs::remove_dir_all(&dir).ok();
}

/// Regression: under concurrency, identical requests raced in the CAS on a
/// shared temp path and ~2% of them returned 500. Every request must succeed
/// and every success must land in the journal exactly once.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_identical_requests_all_recorded() {
    let dir = std::env::temp_dir().join(format!("witness-e2e-conc-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let mock_port = 39720;
    let port = 39721;
    tokio::spawn(mock::serve(mock_port, 0));
    let proxy_dir = dir.clone();
    tokio::spawn(async move {
        proxy::serve(proxy::Options {
            port,
            upstream: format!("http://127.0.0.1:{mock_port}"),
            data_dir: proxy_dir,
            mode: proxy::Mode::Open,
            trust: Vec::new(),
            cache: false, // force the record+forward path every time
            replay: false,
            otlp_endpoint: None,
        })
        .await
        .unwrap();
    });
    wait_for(mock_port).await;
    wait_for(port).await;

    const N: usize = 200;
    let b = body("identical concurrent request", "claude-sonnet-5");
    let mut tasks = Vec::new();
    for _ in 0..N {
        let b = b.clone();
        tasks.push(tokio::spawn(async move { post(port, &b, vec![]).await.0 }));
    }
    let mut ok = 0usize;
    for task in tasks {
        if task.await.unwrap() == 200 {
            ok += 1;
        }
    }
    assert_eq!(ok, N, "every concurrent request must succeed");

    let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
    Journal::verify_chain(&records).unwrap();
    assert_eq!(records.len(), N, "one journal record per request");

    std::fs::remove_dir_all(&dir).ok();
}

/// Scrape the text exposition endpoint.
async fn scrape(port: u16) -> String {
    reqwest::get(format!(
        "http://127.0.0.1:{port}{}",
        witness::proxy::METRICS_PATH
    ))
    .await
    .unwrap()
    .text()
    .await
    .unwrap()
}

/// Value of one fully-qualified series line, labels included.
fn series(text: &str, name: &str) -> f64 {
    let line = text
        .lines()
        .find(|l| {
            l.strip_prefix(name)
                .map(|rest| rest.starts_with(' '))
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no series `{name}` in exposition:\n{text}"));
    line.rsplit(' ').next().unwrap().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_endpoint_counts_traffic() {
    let dir = std::env::temp_dir().join(format!("witness-e2e-metrics-{}", std::process::id()));
    let dead_dir = dir.with_extension("dead");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&dead_dir).ok();

    let mock_port = 39730;
    let port = 39731;
    let replay_port = 39732;
    let dead_port = 39733;
    // Nothing ever binds this: it is how we provoke an upstream error.
    let unbound_port = 39739;

    tokio::spawn(mock::serve(mock_port, 0));
    let proxy_dir = dir.clone();
    tokio::spawn(async move {
        proxy::serve(proxy::Options {
            port,
            upstream: format!("http://127.0.0.1:{mock_port}"),
            data_dir: proxy_dir,
            mode: proxy::Mode::Open,
            trust: Vec::new(),
            cache: true,
            replay: false,
            otlp_endpoint: None,
        })
        .await
        .unwrap();
    });
    wait_for(mock_port).await;
    wait_for(port).await;

    // miss, then hit on the identical body, then one signed miss.
    let b = body("metrics lemma", "claude-sonnet-5");
    assert_eq!(post(port, &b, vec![]).await.2.as_deref(), Some("miss"));
    assert_eq!(post(port, &b, vec![]).await.2.as_deref(), Some("hit"));

    let agent = Keypair::generate().unwrap();
    let signed = body("signed metrics lemma", "claude-sonnet-5");
    let headers = signed_headers(&agent, None, &signed);
    assert_eq!(post(port, &signed, headers).await.0, 200);

    // Scraping is itself free: it must not count as a request or a record.
    let _ = scrape(port).await;
    let text = scrape(port).await;

    assert_eq!(series(&text, "witness_requests_total{cache=\"miss\"}"), 2.0);
    assert_eq!(series(&text, "witness_requests_total{cache=\"hit\"}"), 1.0);
    assert_eq!(
        series(&text, "witness_requests_total{cache=\"replay\"}"),
        0.0
    );
    assert_eq!(series(&text, "witness_requests_signed_total"), 1.0);
    assert_eq!(series(&text, "witness_journal_records"), 3.0);
    assert_eq!(series(&text, "witness_upstream_errors_total"), 0.0);
    assert_eq!(series(&text, "witness_request_duration_seconds_count"), 3.0);
    assert!(series(&text, "witness_request_duration_seconds_sum") > 0.0);
    // Cumulative buckets: the +Inf bucket holds every observation.
    assert_eq!(
        series(
            &text,
            "witness_request_duration_seconds_bucket{le=\"+Inf\"}"
        ),
        3.0
    );
    assert!(
        series(&text, "witness_request_duration_seconds_bucket{le=\"30\"}")
            <= series(
                &text,
                "witness_request_duration_seconds_bucket{le=\"+Inf\"}"
            )
    );

    // The introspection path is excluded from recording, not merely ignored.
    let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|r| !r.path.contains("witness/metrics")));

    // A replay instance counts its own disposition.
    let replay_dir = dir.clone();
    tokio::spawn(async move {
        proxy::serve(proxy::Options {
            port: replay_port,
            upstream: "replay://".into(),
            data_dir: replay_dir,
            mode: proxy::Mode::Open,
            trust: Vec::new(),
            cache: true,
            replay: true,
            otlp_endpoint: None,
        })
        .await
        .unwrap();
    });
    wait_for(replay_port).await;
    assert_eq!(
        post(replay_port, &b, vec![]).await.2.as_deref(),
        Some("replay")
    );
    let text = scrape(replay_port).await;
    assert_eq!(
        series(&text, "witness_requests_total{cache=\"replay\"}"),
        1.0
    );
    assert_eq!(series(&text, "witness_requests_total{cache=\"hit\"}"), 0.0);
    assert_eq!(series(&text, "witness_journal_records"), 4.0);

    // An unreachable upstream is a counted error, not a silent 502.
    tokio::spawn(async move {
        proxy::serve(proxy::Options {
            port: dead_port,
            upstream: format!("http://127.0.0.1:{unbound_port}"),
            data_dir: dead_dir,
            mode: proxy::Mode::Open,
            trust: Vec::new(),
            cache: false,
            replay: false,
            otlp_endpoint: None,
        })
        .await
        .unwrap();
    });
    wait_for(dead_port).await;
    assert_eq!(post(dead_port, &b, vec![]).await.0, 502);
    let text = scrape(dead_port).await;
    assert_eq!(series(&text, "witness_upstream_errors_total"), 1.0);
    assert_eq!(series(&text, "witness_requests_total{cache=\"miss\"}"), 1.0);

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(dir.with_extension("dead")).ok();
}

/// A stand-in OTLP/HTTP collector: accepts the JSON export and flattens every
/// span into one list the test can assert on.
fn otlp_collector(port: u16) -> std::sync::Arc<std::sync::Mutex<Vec<Value>>> {
    use axum::extract::State;
    use axum::routing::post as axum_post;
    use axum::Router;

    let sink: std::sync::Arc<std::sync::Mutex<Vec<Value>>> = Default::default();
    let state = sink.clone();
    tokio::spawn(async move {
        let router = Router::new()
            .route(
                "/v1/traces",
                axum_post(
                    |State(sink): State<std::sync::Arc<std::sync::Mutex<Vec<Value>>>>,
                     raw: String| async move {
                        let parsed: Value = serde_json::from_str(&raw).expect("OTLP body is JSON");
                        let mut got = sink.lock().unwrap();
                        for rs in parsed["resourceSpans"].as_array().unwrap() {
                            for ss in rs["scopeSpans"].as_array().unwrap() {
                                for span in ss["spans"].as_array().unwrap() {
                                    got.push(span.clone());
                                }
                            }
                        }
                        "{}"
                    },
                ),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        axum::serve(listener, router).await.unwrap();
    });
    sink
}

async fn wait_for_spans(
    sink: &std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
    want: usize,
) -> Vec<Value> {
    for _ in 0..200 {
        {
            let got = sink.lock().unwrap();
            if got.len() >= want {
                return got.clone();
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "only {} of {want} spans arrived",
        sink.lock().unwrap().len()
    );
}

fn attr<'a>(span: &'a Value, key: &str) -> &'a Value {
    span["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["key"] == key)
        .unwrap_or_else(|| panic!("span has no attribute {key}: {span}"))
}

fn string_attr(span: &Value, key: &str) -> String {
    attr(span, key)["value"]["stringValue"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn otlp_projection_emits_genai_spans() {
    let dir = std::env::temp_dir().join(format!("witness-e2e-otlp-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();

    let mock_port = 39740;
    let port = 39741;
    let collector_port = 39742;

    let sink = otlp_collector(collector_port);
    tokio::spawn(mock::serve(mock_port, 0));
    let proxy_dir = dir.clone();
    tokio::spawn(async move {
        proxy::serve(proxy::Options {
            port,
            upstream: format!("http://127.0.0.1:{mock_port}"),
            data_dir: proxy_dir,
            mode: proxy::Mode::Open,
            trust: Vec::new(),
            cache: true,
            replay: false,
            // Base URL only: the exporter appends the /v1/traces signal path.
            otlp_endpoint: Some(format!("http://127.0.0.1:{collector_port}")),
        })
        .await
        .unwrap();
    });
    wait_for(mock_port).await;
    wait_for(port).await;
    wait_for(collector_port).await;

    let b = body("otlp lemma", "claude-sonnet-5");
    assert_eq!(post(port, &b, vec![]).await.2.as_deref(), Some("miss"));
    assert_eq!(post(port, &b, vec![]).await.2.as_deref(), Some("hit"));

    let spans = wait_for_spans(&sink, 2).await;
    let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
    assert_eq!(records.len(), 2);

    for span in &spans {
        assert_eq!(span["name"], "chat claude-sonnet-5");
        assert_eq!(span["kind"], 3, "SPAN_KIND_CLIENT");
        assert_eq!(span["status"]["code"], 1, "STATUS_CODE_OK");
        assert_eq!(span["traceId"].as_str().unwrap().len(), 32);
        assert_eq!(span["spanId"].as_str().unwrap().len(), 16);
        assert!(
            span["endTimeUnixNano"].as_str().unwrap()
                >= span["startTimeUnixNano"].as_str().unwrap()
        );

        assert_eq!(string_attr(span, "gen_ai.operation.name"), "chat");
        assert_eq!(string_attr(span, "gen_ai.request.model"), "claude-sonnet-5");
        // Localhost mock is not a known vendor, so semconv's open-enum fallback.
        assert_eq!(string_attr(span, "gen_ai.system"), "_OTHER");
        assert_eq!(string_attr(span, "witness.agent"), "anonymous");
        assert_eq!(string_attr(span, "witness.req_hash").len(), 64);
        assert_eq!(string_attr(span, "witness.resp_hash").len(), 64);

        // Every span points at a real journal record with the same disposition.
        let seq: u64 = attr(span, "witness.seq")["value"]["intValue"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let record = records.iter().find(|r| r.seq == seq).expect("known seq");
        assert_eq!(record.cache, string_attr(span, "witness.cache"));
        assert_eq!(record.req, string_attr(span, "witness.req_hash"));
        assert_eq!(record.resp, string_attr(span, "witness.resp_hash"));
    }

    let dispositions: Vec<String> = spans
        .iter()
        .map(|s| string_attr(s, "witness.cache"))
        .collect();
    assert!(dispositions.contains(&"miss".to_string()));
    assert!(dispositions.contains(&"hit".to_string()));
    assert_ne!(spans[0]["traceId"], spans[1]["traceId"]);

    let text = scrape(port).await;
    assert!(series(&text, "witness_otlp_spans_exported_total") >= 2.0);
    assert_eq!(series(&text, "witness_otlp_spans_dropped_total"), 0.0);

    std::fs::remove_dir_all(&dir).ok();
}
