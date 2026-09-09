//! `witness call` — a signing test client. Builds an Anthropic-style request,
//! signs it with a Pact key + delegation chain, sends it through the proxy,
//! and reports timing plus the witness headers.

use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;
use std::time::Instant;

use crate::identity::{
    chain_to_b64, sign_request, Delegation, Keypair, HDR_DELEGATION, HDR_IDENTITY, HDR_SIGNATURE,
    HDR_TIMESTAMP,
};
use crate::journal::now_ms;

pub struct CallOptions<'a> {
    pub to: &'a str,
    pub path: &'a str,
    pub body: Value,
    pub key: Option<&'a Path>,
    pub chain: Option<&'a Path>,
    pub cache_opt_in: bool,
}

pub async fn call(opts: CallOptions<'_>) -> Result<()> {
    let body_bytes = serde_json::to_vec(&opts.body)?;
    let url = format!("{}{}", opts.to.trim_end_matches('/'), opts.path);
    let client = reqwest::Client::new();
    let mut req = client.post(&url).header("content-type", "application/json");

    if let Some(key_path) = opts.key {
        let key = Keypair::load(key_path)?;
        let ts = now_ms();
        let sig = sign_request(&key, "POST", opts.path, ts, &body_bytes);
        req = req
            .header(HDR_IDENTITY, key.public_hex())
            .header(HDR_TIMESTAMP, ts.to_string())
            .header(HDR_SIGNATURE, sig);
        if let Some(chain_path) = opts.chain {
            let chain: Vec<Delegation> = serde_json::from_slice(
                &std::fs::read(chain_path)
                    .with_context(|| format!("reading chain {}", chain_path.display()))?,
            )?;
            req = req.header(HDR_DELEGATION, chain_to_b64(&chain)?);
        }
    }
    if opts.cache_opt_in {
        req = req.header(crate::proxy::HDR_CACHE_OPT_IN, "allow");
    }

    let started = Instant::now();
    let resp = req
        .body(body_bytes)
        .send()
        .await
        .context("request failed")?;
    let status = resp.status();
    let witness: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter(|(name, _)| name.as_str().starts_with("x-witness-"))
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("?").to_string()))
        .collect();
    let text = resp.text().await?;
    let elapsed = started.elapsed();

    eprintln!("status: {status}   elapsed: {elapsed:?}");
    for (name, value) in &witness {
        eprintln!("{name}: {value}");
    }
    // Pretty-print JSON bodies; pass anything else through.
    match serde_json::from_str::<Value>(&text) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
        Err(_) => println!("{text}"),
    }
    Ok(())
}
