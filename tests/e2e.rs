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
