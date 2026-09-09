//! A fake Anthropic-shaped upstream for demos and tests. Deterministic:
//! the response text embeds a hash of the request, so cache correctness is
//! visible. `--latency-ms` simulates inference time so cache speedups show.

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use axum::Router;
use serde_json::Value;
use std::sync::Arc;

use crate::hash::blake3_hex;

struct MockState {
    latency_ms: u64,
}

pub async fn serve(port: u16, latency_ms: u64) -> Result<()> {
    let state = Arc::new(MockState { latency_ms });
    let router = Router::new().fallback(handle).with_state(state);
    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    eprintln!("witness mock upstream on http://{addr} (latency {latency_ms}ms)");
    axum::serve(listener, router).await?;
    Ok(())
}

async fn handle(State(state): State<Arc<MockState>>, req: Request) -> Response {
    let body = axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap_or_default();
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let model = parsed
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("mock-model")
        .to_string();
    let stream = parsed
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let fingerprint = &blake3_hex(&body)[..16];

    if state.latency_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(state.latency_ms)).await;
    }

    let text = format!("mock completion for request {fingerprint}");
    if stream {
        let events = [
            format!(
                "event: message_start\ndata: {}\n\n",
                serde_json::json!({"type":"message_start","message":{"id":format!("msg_mock_{fingerprint}"),"model":model,"role":"assistant"}})
            ),
            format!(
                "event: content_block_delta\ndata: {}\n\n",
                serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":text}})
            ),
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
        ];
        return Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .body(Body::from(events.concat()))
            .unwrap();
    }

    let response = serde_json::json!({
        "id": format!("msg_mock_{fingerprint}"),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": body.len() / 4, "output_tokens": 12}
    });
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(response.to_string()))
        .unwrap()
}
