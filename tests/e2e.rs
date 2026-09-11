//! End-to-end: mock upstream + proxy in-process, exercising record → cache →
//! identity enforcement → replay → commit → prove.

use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::{Duration, Instant};

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
            peers: Vec::new(),
            peer_token: None,
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
            peers: Vec::new(),
            peer_token: None,
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
            peers: Vec::new(),
            peer_token: None,
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
            peers: Vec::new(),
            peer_token: None,
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
            peers: Vec::new(),
            peer_token: None,
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
            peers: Vec::new(),
            peer_token: None,
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
            peers: Vec::new(),
            peer_token: None,
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
            peers: Vec::new(),
            peer_token: None,
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

/// The thesis, end to end: a response nobody would reuse on sampling grounds
/// becomes reusable once an external check vouches for it. The temperature
/// never changes; only what is known about the answer does.
#[tokio::test(flavor = "multi_thread")]
async fn oracle_attestation_unlocks_a_nondeterministic_request() {
    let dir = std::env::temp_dir().join(format!("witness-e2e-oracle-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let mock_port = 39820;
    let port = 39821;

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
            peers: Vec::new(),
            peer_token: None,
        })
        .await
        .unwrap();
    });
    wait_for(mock_port).await;
    wait_for(port).await;

    // temperature 1: recorded, never reused, however often it is asked.
    let mut hot = body("attest this sampled answer", "claude-sonnet-5");
    hot["temperature"] = json!(1.0);
    let (status, first, cache) = post(port, &hot, vec![]).await;
    assert_eq!(status, 200);
    assert_eq!(cache.as_deref(), Some("miss"));
    assert_eq!(post(port, &hot, vec![]).await.2.as_deref(), Some("miss"));

    // An oracle reads the recorded response body and exits 0.
    let attestation = witness::oracle::attest(witness::oracle::AttestOptions {
        data_dir: &dir,
        seq: 1,
        oracle: "grep -q mock",
        name: "grep",
        key: None,
        method: witness::oracle::DEFAULT_METHOD,
    })
    .unwrap();
    assert!(attestation.verified, "the mock's text contains \"mock\"");

    // Same body, same temperature, now served from the record.
    let (status, third, cache) = post(port, &hot, vec![]).await;
    assert_eq!(status, 200);
    assert_eq!(
        cache.as_deref(),
        Some("hit"),
        "an attested request is reusable whatever its sampling parameters"
    );
    assert_eq!(third, first, "the hit must be the attested bytes");

    // A different nondeterministic request is untouched by that attestation.
    let mut other = body("some other sampled answer", "claude-sonnet-5");
    other["temperature"] = json!(1.0);
    assert_eq!(post(port, &other, vec![]).await.2.as_deref(), Some("miss"));
    assert_eq!(post(port, &other, vec![]).await.2.as_deref(), Some("miss"));

    // The attestation is in the same chain, naming the command that vouched.
    let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
    Journal::verify_chain(&records).unwrap();
    let attest_record = records
        .iter()
        .find(|r| r.path == "attest:grep:1")
        .expect("attestation is journaled");
    assert_eq!(attest_record.seq, attestation.seq.unwrap());
    assert_eq!(attest_record.req, records[0].hash);
    let cas = witness::cas::Cas::open(&dir).unwrap();
    let evidence: Value =
        serde_json::from_slice(&cas.get(&attest_record.resp).unwrap().unwrap()).unwrap();
    assert_eq!(evidence["oracle"], "grep -q mock");
    assert_eq!(evidence["req_key"], attestation.req_key);

    // And the marker the proxy consulted is listed for an operator.
    let markers = witness::oracle::list(&dir).unwrap();
    assert_eq!(markers.len(), 1);
    assert_eq!(markers[0].req_key, attestation.req_key);

    // A refuted oracle over that same record leaves the journal untouched.
    let before = records.len();
    let refuted = witness::oracle::attest(witness::oracle::AttestOptions {
        data_dir: &dir,
        seq: 1,
        oracle: "grep -q 'this string is not in any mock response'",
        name: "grep",
        key: None,
        method: witness::oracle::DEFAULT_METHOD,
    })
    .unwrap();
    assert!(!refuted.verified);
    assert_eq!(
        Journal::read_all_from(&dir.join("journal.log"))
            .unwrap()
            .len(),
        before,
        "a refutation must not append a record"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// --- fleet mode v1: squid-sibling peer cache ---------------------------------
//
// Ports for these tests come from the 39840-39869 block. The `dead_*` ports are
// never bound by anything: they are how an instance is given an upstream or a
// peer that cannot answer.

const FLEET_MOCK_PORT: u16 = 39840;
const FLEET_A_PORT: u16 = 39841;
const FLEET_B_PORT: u16 = 39842;
const FLEET_DEAD_UPSTREAM: u16 = 39849;

const TOKEN_MOCK_PORT: u16 = 39850;
const TOKEN_A_PORT: u16 = 39851;
const TOKEN_B_PORT: u16 = 39852;
const TOKEN_DEAD_UPSTREAM: u16 = 39859;

const ATTEST_MOCK_PORT: u16 = 39843;
const ATTEST_A_PORT: u16 = 39844;
const ATTEST_B_PORT: u16 = 39845;
const ATTEST_DEAD_UPSTREAM: u16 = 39848;

const SLOW_MOCK_PORT: u16 = 39860;
const SLOW_PROXY_PORT: u16 = 39861;
const DEAD_PEER_PORT: u16 = 39869;

/// A witness instance for the fleet tests. Everything not named is the
/// recording default: open mode, cache on, no OTLP.
fn fleet_instance(
    port: u16,
    dir: &std::path::Path,
    upstream: u16,
    peers: Vec<String>,
    peer_token: Option<String>,
) {
    let data_dir = dir.to_path_buf();
    tokio::spawn(async move {
        proxy::serve(proxy::Options {
            port,
            upstream: format!("http://127.0.0.1:{upstream}"),
            data_dir,
            mode: proxy::Mode::Open,
            trust: Vec::new(),
            cache: true,
            replay: false,
            otlp_endpoint: None,
            peers,
            peer_token,
        })
        .await
        .unwrap();
    });
}

fn peer_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// Raw GET against an instance's peer cache route, bypassing the proxy path.
async fn peer_read(port: u16, req_key: &str, token: Option<&str>) -> (u16, Option<String>, String) {
    let mut req = reqwest::Client::new().get(format!(
        "http://127.0.0.1:{port}{}{req_key}",
        witness::proxy::PEER_CACHE_PREFIX
    ));
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let resp_hash = resp
        .headers()
        .get("x-witness-resp")
        .map(|v| v.to_str().unwrap().to_string());
    (status, resp_hash, resp.text().await.unwrap())
}

/// Instance B answers out of instance A's cache. B's upstream is an unbound
/// port, so a peer miss could only produce a 502: a 200 here cannot have come
/// from anywhere but the sibling.
#[tokio::test(flavor = "multi_thread")]
async fn peer_cache_answers_without_any_upstream() {
    let dir_a = std::env::temp_dir().join(format!("witness-e2e-fleet-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("witness-e2e-fleet-b-{}", std::process::id()));
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();

    tokio::spawn(mock::serve(FLEET_MOCK_PORT, 0));
    fleet_instance(FLEET_A_PORT, &dir_a, FLEET_MOCK_PORT, Vec::new(), None);
    wait_for(FLEET_MOCK_PORT).await;
    wait_for(FLEET_A_PORT).await;

    // A warms the entry against the real (mock) upstream.
    let b = body("fleet lemma F1", "claude-sonnet-5");
    let (status, warmed, cache) = post(FLEET_A_PORT, &b, vec![]).await;
    assert_eq!(status, 200);
    assert_eq!(cache.as_deref(), Some("miss"));

    // B has a dead upstream and one peer: A.
    fleet_instance(
        FLEET_B_PORT,
        &dir_b,
        FLEET_DEAD_UPSTREAM,
        vec![peer_url(FLEET_A_PORT)],
        None,
    );
    wait_for(FLEET_B_PORT).await;

    let (status, from_peer, cache) = post(FLEET_B_PORT, &b, vec![]).await;
    assert_eq!(status, 200, "B must be served by its peer: {from_peer}");
    assert_eq!(cache.as_deref(), Some("peer"));
    assert_eq!(
        from_peer, warmed,
        "a peer hit is byte-identical to the record"
    );

    // B journals the call as its own, naming the sibling it inherited it from.
    let records = Journal::read_all_from(&dir_b.join("journal.log")).unwrap();
    Journal::verify_chain(&records).unwrap();
    assert_eq!(
        records.len(),
        1,
        "one local record for the peer-served call"
    );
    assert_eq!(records[0].cache, "peer");
    assert_eq!(
        records[0].upstream,
        format!("peer:127.0.0.1:{FLEET_A_PORT}")
    );
    assert_eq!(records[0].status, 200);
    assert_eq!(records[0].model.as_deref(), Some("claude-sonnet-5"));

    // The bytes landed in B's own CAS, so B is a witness in its own right.
    let cas_b = witness::cas::Cas::open(&dir_b).unwrap();
    assert_eq!(
        cas_b.get(&records[0].resp).unwrap().unwrap(),
        warmed.to_string().into_bytes()
    );

    let text = scrape(FLEET_B_PORT).await;
    assert_eq!(series(&text, "witness_requests_total{cache=\"peer\"}"), 1.0);
    assert_eq!(series(&text, "witness_peer_hits_total"), 1.0);
    assert_eq!(series(&text, "witness_peer_errors_total"), 0.0);
    assert_eq!(series(&text, "witness_upstream_errors_total"), 0.0);
    assert_eq!(series(&text, "witness_requests_total{cache=\"miss\"}"), 0.0);

    // The peer answer was adopted, not proxied: the repeat is a local hit and
    // never touches A again.
    let (status, again, cache) = post(FLEET_B_PORT, &b, vec![]).await;
    assert_eq!(status, 200);
    assert_eq!(cache.as_deref(), Some("hit"));
    assert_eq!(again, warmed);

    // Serving a peer read is not a model call: A's journal is untouched by it.
    let records_a = Journal::read_all_from(&dir_a.join("journal.log")).unwrap();
    assert_eq!(records_a.len(), 1, "A journals only its own upstream call");
    assert!(records_a.iter().all(|r| !r.path.contains("witness/peer")));

    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

/// The peer token is a real boundary. A mismatched token is a 401 on the wire,
/// which the client counts as a peer error and steps past, straight into an
/// upstream that cannot answer, so the call fails rather than silently
/// succeeding through an unauthenticated path.
#[tokio::test(flavor = "multi_thread")]
async fn peer_token_mismatch_is_an_error_not_a_hit() {
    let dir_a = std::env::temp_dir().join(format!("witness-e2e-token-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("witness-e2e-token-b-{}", std::process::id()));
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();

    tokio::spawn(mock::serve(TOKEN_MOCK_PORT, 0));
    fleet_instance(
        TOKEN_A_PORT,
        &dir_a,
        TOKEN_MOCK_PORT,
        Vec::new(),
        Some("fleet-secret".into()),
    );
    wait_for(TOKEN_MOCK_PORT).await;
    wait_for(TOKEN_A_PORT).await;

    let b = body("fleet lemma F2", "claude-sonnet-5");
    let (status, warmed, _) = post(TOKEN_A_PORT, &b, vec![]).await;
    assert_eq!(status, 200);

    // The route itself: unauthenticated and wrong-token reads are refused,
    // the right token gets the recorded bytes.
    let req_key = witness::hash::request_key("POST", "/v1/messages", b.to_string().as_bytes());
    assert_eq!(peer_read(TOKEN_A_PORT, &req_key, None).await.0, 401);
    assert_eq!(
        peer_read(TOKEN_A_PORT, &req_key, Some("not-the-secret"))
            .await
            .0,
        401
    );
    let (status, resp_hash, text) = peer_read(TOKEN_A_PORT, &req_key, Some("fleet-secret")).await;
    assert_eq!(status, 200);
    assert_eq!(resp_hash.unwrap().len(), 64);
    assert_eq!(text, warmed.to_string());
    // An unknown key is a clean 404, not an error and not a probe surface.
    assert_eq!(
        peer_read(TOKEN_A_PORT, &"ab".repeat(32), Some("fleet-secret"))
            .await
            .0,
        404
    );

    // B holds the wrong secret, so A's cache is closed to it.
    fleet_instance(
        TOKEN_B_PORT,
        &dir_b,
        TOKEN_DEAD_UPSTREAM,
        vec![peer_url(TOKEN_A_PORT)],
        Some("wrong-secret".into()),
    );
    wait_for(TOKEN_B_PORT).await;

    let (status, _, _) = post(TOKEN_B_PORT, &b, vec![]).await;
    assert_eq!(
        status, 502,
        "a refused peer must fall through to the upstream, not be treated as a hit"
    );

    let text = scrape(TOKEN_B_PORT).await;
    assert_eq!(series(&text, "witness_peer_errors_total"), 1.0);
    assert_eq!(series(&text, "witness_peer_hits_total"), 0.0);
    assert_eq!(series(&text, "witness_upstream_errors_total"), 1.0);

    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

/// A dead peer costs the hot path an error counter and nothing else: the call
/// still completes through the upstream, well inside the per-peer budget.
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_peer_does_not_stall_the_request() {
    let dir = std::env::temp_dir().join(format!("witness-e2e-deadpeer-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();

    tokio::spawn(mock::serve(SLOW_MOCK_PORT, 0));
    fleet_instance(
        SLOW_PROXY_PORT,
        &dir,
        SLOW_MOCK_PORT,
        vec![peer_url(DEAD_PEER_PORT)],
        None,
    );
    wait_for(SLOW_MOCK_PORT).await;
    wait_for(SLOW_PROXY_PORT).await;

    let b = body("fleet lemma F3", "claude-sonnet-5");
    let started = Instant::now();
    let (status, _, cache) = post(SLOW_PROXY_PORT, &b, vec![]).await;
    let elapsed = started.elapsed();
    assert_eq!(status, 200);
    assert_eq!(cache.as_deref(), Some("miss"));
    assert!(
        elapsed < Duration::from_secs(1),
        "a dead peer must not stall the hot path; took {elapsed:?}"
    );

    let text = scrape(SLOW_PROXY_PORT).await;
    assert_eq!(series(&text, "witness_peer_errors_total"), 1.0);
    assert_eq!(series(&text, "witness_peer_hits_total"), 0.0);
    assert_eq!(series(&text, "witness_requests_total{cache=\"miss\"}"), 1.0);

    // The upstream really served it: one local record, named upstream.
    let records = Journal::read_all_from(&dir.join("journal.log")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].cache, "miss");
    assert_eq!(
        records[0].upstream,
        format!("http://127.0.0.1:{SLOW_MOCK_PORT}")
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Where fleet mode and verifier oracles meet. A peer is asked under exactly
/// the condition that would have allowed a local hit, and since the oracle
/// work landed that condition includes an attestation. A temperature 1.0
/// request therefore gets no peer lookup at all until this instance has an
/// attestation for it, and then the sibling can answer it.
///
/// The marker is written directly rather than through `witness attest`,
/// because the case being pinned is the one where a marker exists here and
/// the object does not: attested earlier, pruned since, still held next door.
#[tokio::test(flavor = "multi_thread")]
async fn an_attested_request_is_worth_asking_a_peer_for() {
    let dir_a = std::env::temp_dir().join(format!("witness-e2e-fleetatt-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("witness-e2e-fleetatt-b-{}", std::process::id()));
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();

    tokio::spawn(mock::serve(ATTEST_MOCK_PORT, 0));
    fleet_instance(ATTEST_A_PORT, &dir_a, ATTEST_MOCK_PORT, Vec::new(), None);
    fleet_instance(
        ATTEST_B_PORT,
        &dir_b,
        ATTEST_DEAD_UPSTREAM,
        vec![peer_url(ATTEST_A_PORT)],
        None,
    );
    wait_for(ATTEST_MOCK_PORT).await;
    wait_for(ATTEST_A_PORT).await;
    wait_for(ATTEST_B_PORT).await;

    // A records a sampled answer. Recording is unconditional, so A holds the
    // bytes even though nothing would reuse them yet.
    let mut hot = body("fleet lemma F4", "claude-sonnet-5");
    hot["temperature"] = json!(1.0);
    let (status, recorded, cache) = post(ATTEST_A_PORT, &hot, vec![]).await;
    assert_eq!(status, 200);
    assert_eq!(cache.as_deref(), Some("miss"));

    // B will not spend a peer lookup on a request it could not reuse anyway.
    let (status, _, _) = post(ATTEST_B_PORT, &hot, vec![]).await;
    assert_eq!(
        status, 502,
        "B's upstream is dead and nothing else may serve it"
    );
    let text = scrape(ATTEST_B_PORT).await;
    assert_eq!(
        series(&text, "witness_peer_errors_total"),
        0.0,
        "a nondeterministic request must not even reach the peers"
    );
    assert_eq!(series(&text, "witness_peer_hits_total"), 0.0);

    // An oracle vouches for this exact request on this instance.
    let req_key = witness::hash::request_key("POST", "/v1/messages", hot.to_string().as_bytes());
    let attested = witness::oracle::attested_dir(&dir_b);
    std::fs::create_dir_all(&attested).unwrap();
    std::fs::write(
        attested.join(&req_key),
        serde_json::to_vec(&witness::oracle::Marker {
            req_key: req_key.clone(),
            name: "grep".into(),
            seq: 0,
            target_seq: 0,
            attester: witness::oracle::ANONYMOUS_ATTESTER.into(),
            ts_ms: now_ms(),
        })
        .unwrap(),
    )
    .unwrap();

    // Same body, same temperature, and now worth asking the sibling for.
    let (status, from_peer, cache) = post(ATTEST_B_PORT, &hot, vec![]).await;
    assert_eq!(status, 200);
    assert_eq!(cache.as_deref(), Some("peer"));
    assert_eq!(from_peer, recorded);

    let records = Journal::read_all_from(&dir_b.join("journal.log")).unwrap();
    Journal::verify_chain(&records).unwrap();
    assert_eq!(
        records.len(),
        1,
        "the 502 journaled nothing; the peer hit did"
    );
    assert_eq!(records[0].cache, "peer");
    assert_eq!(
        records[0].upstream,
        format!("peer:127.0.0.1:{ATTEST_A_PORT}")
    );

    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}
