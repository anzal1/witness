//! Pact identity layer: Ed25519 keypairs, narrowing-only delegation chains,
//! and per-request signatures — all verifiable locally, no network calls.
//!
//! Chain shape: root (human) key signs a delegation to agent A; A may
//! sub-delegate to B with equal-or-narrower capabilities. The request itself
//! is signed by the final subject's key. Verifiers check: every link
//! signature, subject→issuer continuity, capability narrowing, expiry, and
//! the request signature — then decide whether the chain's root is trusted.

use anyhow::{bail, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::hash::{blake3_hex, canonical_json};
use crate::journal::now_ms;

pub const HDR_IDENTITY: &str = "x-pact-identity";
pub const HDR_TIMESTAMP: &str = "x-pact-timestamp";
pub const HDR_SIGNATURE: &str = "x-pact-signature";
pub const HDR_DELEGATION: &str = "x-pact-delegation";

/// A request signature is valid for this window around the proxy's clock.
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

// ---------- keys ----------

pub struct Keypair {
    pub signing: SigningKey,
}

impl Keypair {
    pub fn generate() -> Result<Self> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(|e| anyhow::anyhow!("gathering entropy: {e}"))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&secret),
        })
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    /// Save as `<path>.key` (secret, 0600) and `<path>.pub` (public).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let key_path = path.with_extension("key");
        std::fs::write(&key_path, hex::encode(self.signing.to_bytes()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::write(path.with_extension("pub"), self.public_hex())?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let key_path = if path.extension().is_some() {
            path.to_path_buf()
        } else {
            path.with_extension("key")
        };
        let hex_str = std::fs::read_to_string(&key_path)
            .with_context(|| format!("reading key file {}", key_path.display()))?;
        let bytes: [u8; 32] = hex::decode(hex_str.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("key file must contain 32 hex-encoded bytes"))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&bytes),
        })
    }
}

pub fn parse_pubkey(hex_str: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_str.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 hex-encoded bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 public key")
}

// ---------- capabilities ----------

/// Capabilities are strings like "model:claude-*" or "invoke". A parent cap
/// covers a child cap if they are equal, or the parent ends in '*' and the
/// child starts with the parent's prefix. Narrowing-only means every child
/// cap must be covered by some parent cap.
pub fn cap_covers(parent: &str, child: &str) -> bool {
    if let Some(prefix) = parent.strip_suffix('*') {
        child.starts_with(prefix)
    } else {
        parent == child
    }
}

pub fn caps_narrow(parent: &[String], child: &[String]) -> bool {
    child
        .iter()
        .all(|c| parent.iter().any(|p| cap_covers(p, c)))
}

/// Does this capability set permit invoking `model`?
pub fn caps_allow_model(caps: &[String], model: &str) -> bool {
    let want = format!("model:{model}");
    caps.iter().any(|c| cap_covers(c, &want))
}

// ---------- delegations ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub issuer: String,
    pub subject: String,
    pub capabilities: Vec<String>,
    pub expires_ms: u64,
    pub sig: String,
}

impl Delegation {
    fn signing_bytes(
        issuer: &str,
        subject: &str,
        capabilities: &[String],
        expires_ms: u64,
    ) -> Vec<u8> {
        let value = serde_json::json!({
            "issuer": issuer,
            "subject": subject,
            "capabilities": capabilities,
            "expires_ms": expires_ms,
        });
        canonical_json(&value)
    }

    pub fn issue(
        issuer: &Keypair,
        subject_pub_hex: &str,
        capabilities: Vec<String>,
        ttl_secs: u64,
    ) -> Result<Self> {
        parse_pubkey(subject_pub_hex).context("subject public key")?;
        let issuer_hex = issuer.public_hex();
        let expires_ms = now_ms() + ttl_secs * 1000;
        let msg = Self::signing_bytes(&issuer_hex, subject_pub_hex, &capabilities, expires_ms);
        let sig = issuer.signing.sign(&msg);
        Ok(Self {
            issuer: issuer_hex,
            subject: subject_pub_hex.to_string(),
            capabilities,
            expires_ms,
            sig: hex::encode(sig.to_bytes()),
        })
    }

    pub fn verify_signature(&self) -> Result<()> {
        let key = parse_pubkey(&self.issuer)?;
        let msg = Self::signing_bytes(
            &self.issuer,
            &self.subject,
            &self.capabilities,
            self.expires_ms,
        );
        let sig_bytes: [u8; 64] = hex::decode(&self.sig)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("delegation signature must be 64 bytes"))?;
        key.verify(&msg, &Signature::from_bytes(&sig_bytes))
            .context("delegation signature invalid")
    }
}

/// A verified chain: who anchors it, who acts under it, what they may do.
pub struct VerifiedChain {
    pub root: String,
    pub agent: String,
    pub capabilities: Vec<String>,
}

/// Verify a delegation chain end to end. `now` is the proxy's clock (ms).
pub fn verify_chain(chain: &[Delegation], now: u64) -> Result<VerifiedChain> {
    if chain.is_empty() {
        bail!("empty delegation chain");
    }
    let mut effective: Option<Vec<String>> = None;
    for (i, link) in chain.iter().enumerate() {
        link.verify_signature()
            .with_context(|| format!("chain link {i}"))?;
        if now > link.expires_ms {
            bail!("chain link {i} expired");
        }
        if i > 0 && chain[i - 1].subject != link.issuer {
            bail!("chain link {i}: issuer is not the previous subject");
        }
        match &effective {
            None => effective = Some(link.capabilities.clone()),
            Some(parent) => {
                if !caps_narrow(parent, &link.capabilities) {
                    bail!("chain link {i} escalates capabilities beyond its parent grant");
                }
                effective = Some(link.capabilities.clone());
            }
        }
    }
    Ok(VerifiedChain {
        root: chain[0].issuer.clone(),
        agent: chain.last().unwrap().subject.clone(),
        capabilities: effective.unwrap(),
    })
}

// ---------- request signing ----------

pub fn request_signing_bytes(method: &str, path: &str, timestamp_ms: u64, body: &[u8]) -> Vec<u8> {
    format!("{method}\n{path}\n{timestamp_ms}\n{}", blake3_hex(body)).into_bytes()
}

pub fn sign_request(
    key: &Keypair,
    method: &str,
    path: &str,
    timestamp_ms: u64,
    body: &[u8],
) -> String {
    let msg = request_signing_bytes(method, path, timestamp_ms, body);
    hex::encode(key.signing.sign(&msg).to_bytes())
}

pub fn verify_request_signature(
    identity_hex: &str,
    sig_hex: &str,
    method: &str,
    path: &str,
    timestamp_ms: u64,
    body: &[u8],
    now: u64,
) -> Result<()> {
    if now.abs_diff(timestamp_ms) > MAX_CLOCK_SKEW_MS {
        bail!("request timestamp outside allowed clock skew");
    }
    let key = parse_pubkey(identity_hex)?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("request signature must be 64 bytes"))?;
    let msg = request_signing_bytes(method, path, timestamp_ms, body);
    key.verify(&msg, &Signature::from_bytes(&sig_bytes))
        .context("request signature invalid")
}

// ---------- chain (de)serialization for headers/files ----------

pub fn chain_to_b64(chain: &[Delegation]) -> Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(chain)?))
}

pub fn chain_from_b64(encoded: &str) -> Result<Vec<Delegation>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .context("delegation header is not valid base64")?;
    serde_json::from_slice(&bytes).context("delegation header is not a valid chain")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp() -> Keypair {
        Keypair::generate().unwrap()
    }

    #[test]
    fn narrowing_rules() {
        assert!(cap_covers("model:*", "model:claude-sonnet-5"));
        assert!(cap_covers("model:claude-*", "model:claude-opus-5"));
        assert!(!cap_covers("model:claude-*", "model:gpt-6"));
        assert!(caps_narrow(&["model:*".into()], &["model:claude-*".into()]));
        assert!(!caps_narrow(
            &["model:claude-*".into()],
            &["model:*".into()]
        ));
    }

    #[test]
    fn chain_verifies_and_blocks_escalation() {
        let human = kp();
        let agent_a = kp();
        let agent_b = kp();
        let d1 = Delegation::issue(
            &human,
            &agent_a.public_hex(),
            vec!["model:claude-*".into()],
            3600,
        )
        .unwrap();
        let d2 = Delegation::issue(
            &agent_a,
            &agent_b.public_hex(),
            vec!["model:claude-sonnet-5".into()],
            3600,
        )
        .unwrap();
        let verified = verify_chain(&[d1.clone(), d2], now_ms()).unwrap();
        assert_eq!(verified.root, human.public_hex());
        assert_eq!(verified.agent, agent_b.public_hex());
        assert!(caps_allow_model(&verified.capabilities, "claude-sonnet-5"));
        assert!(!caps_allow_model(&verified.capabilities, "claude-opus-5"));

        // Escalation attempt: sub-delegate broader than the parent grant.
        let d2_esc = Delegation::issue(
            &agent_a,
            &agent_b.public_hex(),
            vec!["model:*".into()],
            3600,
        )
        .unwrap();
        assert!(verify_chain(&[d1, d2_esc], now_ms()).is_err());
    }

    #[test]
    fn forged_link_rejected() {
        let human = kp();
        let mallory = kp();
        let agent = kp();
        let mut d =
            Delegation::issue(&mallory, &agent.public_hex(), vec!["model:*".into()], 3600).unwrap();
        // Claim the human issued it.
        d.issuer = human.public_hex();
        assert!(verify_chain(&[d], now_ms()).is_err());
    }

    #[test]
    fn request_signature_roundtrip() {
        let agent = kp();
        let ts = now_ms();
        let sig = sign_request(&agent, "POST", "/v1/messages", ts, b"{}");
        verify_request_signature(
            &agent.public_hex(),
            &sig,
            "POST",
            "/v1/messages",
            ts,
            b"{}",
            ts,
        )
        .unwrap();
        assert!(verify_request_signature(
            &agent.public_hex(),
            &sig,
            "POST",
            "/v1/messages",
            ts,
            b"{tampered}",
            ts
        )
        .is_err());
        assert!(verify_request_signature(
            &agent.public_hex(),
            &sig,
            "POST",
            "/v1/messages",
            ts,
            b"{}",
            ts + MAX_CLOCK_SKEW_MS + 1
        )
        .is_err());
    }

    #[test]
    fn chain_b64_roundtrip() {
        let human = kp();
        let agent = kp();
        let d = Delegation::issue(&human, &agent.public_hex(), vec!["model:*".into()], 60).unwrap();
        let encoded = chain_to_b64(&[d]).unwrap();
        let decoded = chain_from_b64(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].issuer, human.public_hex());
    }
}
