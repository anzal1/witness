//! Anchoring: publish a Merkle commitment to Sigstore's Rekor transparency
//! log, so the commitment stops being a local assertion and becomes something
//! a third party can check without trusting the operator.
//!
//! What goes into the log is a `hashedrekord` entry over the commitment file
//! itself: its SHA-256, an Ed25519 signature by the operator's key, and that
//! key in SPKI/PEM form. Rekor countersigns and timestamps the entry, which
//! is the property a local file cannot have. It proves the root existed
//! before the log's inclusion time, so a root cannot be back-dated after the
//! fact. Rekor never sees the journal, only the digest of the commitment.

use anyhow::{bail, Context, Result};
use base64::Engine;
// Re-exported through ed25519-dalek rather than depended on directly, so the
// SPKI stack stays pinned to whatever version the signing crate resolved.
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
use ed25519_dalek::{Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::identity::Keypair;
use crate::journal::now_ms;

/// Sigstore's public instance. Overridable for private or test logs.
pub const REKOR_URL: &str = "https://rekor.sigstore.dev";

const ENTRIES_PATH: &str = "/api/v1/log/entries";

/// What `witness anchor` writes next to the commitment it anchored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorRecord {
    /// Log this entry lives in.
    pub rekor_url: String,
    /// Rekor entry UUID: the handle a third party looks the entry up by.
    pub uuid: String,
    pub log_index: u64,
    /// Rekor's own inclusion timestamp (seconds), if the log returned one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrated_time: Option<u64>,
    /// SHA-256 of the commitment file, hex. This is what the entry attests to.
    pub artifact_sha256: String,
    /// Merkle root carried by that commitment, copied for readability.
    pub root: String,
    /// Ed25519 key that signed the entry, hex (same encoding as Pact ids).
    pub signer: String,
    pub ts_ms: u64,
}

pub struct AnchorOptions<'a> {
    pub commitment: &'a Path,
    pub key: &'a Path,
    pub rekor_url: &'a str,
    pub dry_run: bool,
}

// ---------- entry construction (pure, testable) ----------

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Ed25519 verifying key as an SPKI PEM block. Rekor's `hashedrekord` takes
/// x509/PEM public keys, not the raw 32 bytes Pact passes around.
pub fn public_key_pem(key: &VerifyingKey) -> Result<String> {
    key.to_public_key_pem(LineEnding::LF)
        .context("encoding Ed25519 public key as SPKI PEM")
}

pub fn public_key_from_pem(pem: &str) -> Result<VerifyingKey> {
    VerifyingKey::from_public_key_pem(pem).context("decoding SPKI PEM public key")
}

/// Build the Rekor `hashedrekord` proposed entry for an artifact. The log
/// stores only the digest and the signature, never the artifact bytes.
pub fn proposed_entry(artifact: &[u8], key: &Keypair) -> Result<Value> {
    let signature = key.signing.sign(artifact);
    let pem = public_key_pem(&key.signing.verifying_key())?;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": sha256_hex(artifact),
                }
            },
            "signature": {
                "content": b64.encode(signature.to_bytes()),
                "publicKey": { "content": b64.encode(pem.as_bytes()) },
            }
        }
    }))
}

/// The artifact digest a Rekor entry attests to. `entry` is one value from
/// the log's `{uuid: entry}` response map; its `body` is base64 of the
/// canonicalized entry JSON.
pub fn artifact_hash_from_entry(entry: &Value) -> Result<String> {
    let body = entry["body"]
        .as_str()
        .context("Rekor entry has no body field")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(body)
        .context("Rekor entry body is not valid base64")?;
    let parsed: Value =
        serde_json::from_slice(&decoded).context("Rekor entry body is not valid JSON")?;
    parsed["spec"]["data"]["hash"]["value"]
        .as_str()
        .map(str::to_string)
        .context("Rekor entry carries no spec.data.hash.value")
}

/// `<commitment>.anchor.json`: the receipt sits beside its commitment.
pub fn anchor_path(commitment: &Path) -> PathBuf {
    commitment.with_extension("anchor.json")
}

fn read_commitment(path: &Path) -> Result<(Vec<u8>, Value)> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading commitment {}", path.display()))?;
    let parsed: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a valid commitment file", path.display()))?;
    if parsed["root"].as_str().is_none() {
        bail!("{} has no Merkle root; is it a commitment?", path.display());
    }
    Ok((bytes, parsed))
}

// ---------- commands ----------

pub async fn anchor(opts: AnchorOptions<'_>) -> Result<()> {
    let (artifact, commitment) = read_commitment(opts.commitment)?;
    let key = Keypair::load(opts.key)?;
    let entry = proposed_entry(&artifact, &key)?;
    let rekor_url = opts.rekor_url.trim_end_matches('/');

    if opts.dry_run {
        println!("{}", serde_json::to_string_pretty(&entry)?);
        eprintln!(
            "dry run: would POST the above to {rekor_url}{ENTRIES_PATH}\ncommitment: {}  sha256: {}",
            opts.commitment.display(),
            sha256_hex(&artifact)
        );
        return Ok(());
    }

    let url = format!("{rekor_url}{ENTRIES_PATH}");
    let resp = reqwest::Client::new()
        .post(&url)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(serde_json::to_vec(&entry)?)
        .send()
        .await
        .with_context(|| format!("posting entry to {url}"))?;

    let status = resp.status();
    // Rekor de-duplicates: an identical entry comes back as 409 with the
    // existing entry's location, which is a success for our purposes.
    let existing_uuid = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit('/').next())
        .map(str::to_string);
    let text = resp.text().await?;

    let (uuid, log_index, integrated_time) = if status.as_u16() == 409 {
        let uuid = existing_uuid
            .filter(|u| !u.is_empty())
            .context("Rekor reports a duplicate entry but returned no location")?;
        let entry = fetch_entry(rekor_url, &uuid).await?;
        eprintln!("this commitment was already anchored; reusing the existing entry");
        (
            uuid,
            entry["logIndex"].as_u64().unwrap_or_default(),
            entry["integratedTime"].as_u64(),
        )
    } else if status.is_success() {
        let body: Value =
            serde_json::from_str(&text).context("Rekor response is not valid JSON")?;
        let (uuid, entry) = body
            .as_object()
            .and_then(|m| m.iter().next())
            .context("Rekor returned an empty entry map")?;
        (
            uuid.clone(),
            entry["logIndex"].as_u64().unwrap_or_default(),
            entry["integratedTime"].as_u64(),
        )
    } else {
        bail!("Rekor rejected the entry ({status}): {text}");
    };

    let record = AnchorRecord {
        rekor_url: rekor_url.to_string(),
        uuid: uuid.clone(),
        log_index,
        integrated_time,
        artifact_sha256: sha256_hex(&artifact),
        root: commitment["root"].as_str().unwrap_or_default().to_string(),
        signer: key.public_hex(),
        ts_ms: now_ms(),
    };
    let out = anchor_path(opts.commitment);
    std::fs::write(&out, serde_json::to_vec_pretty(&record)?)?;

    println!("{uuid}");
    eprintln!(
        "anchored root {} as Rekor entry {} (logIndex {})\nreceipt: {}\nverify:  witness anchor-verify --commitment {}\n         rekor-cli get --uuid {} --rekor_server {}\n         https://search.sigstore.dev/?uuid={}",
        record.root,
        record.uuid,
        record.log_index,
        out.display(),
        opts.commitment.display(),
        record.uuid,
        rekor_url,
        record.uuid,
    );
    Ok(())
}

pub async fn verify(commitment: &Path, rekor_url: Option<&str>) -> Result<()> {
    let (artifact, _) = read_commitment(commitment)?;
    let receipt_path = anchor_path(commitment);
    let receipt: AnchorRecord =
        serde_json::from_slice(&std::fs::read(&receipt_path).with_context(|| {
            format!(
                "no anchor receipt at {}; run `witness anchor` first",
                receipt_path.display()
            )
        })?)
        .with_context(|| format!("{} is not a valid anchor receipt", receipt_path.display()))?;

    let url = rekor_url
        .unwrap_or(&receipt.rekor_url)
        .trim_end_matches('/');
    let entry = fetch_entry(url, &receipt.uuid).await?;
    let logged = artifact_hash_from_entry(&entry)?;
    let local = sha256_hex(&artifact);

    if logged != local {
        bail!(
            "MISMATCH: Rekor entry {} attests to sha256 {logged}, but {} hashes to {local}",
            receipt.uuid,
            commitment.display()
        );
    }
    if receipt.artifact_sha256 != local {
        bail!(
            "MISMATCH: receipt {} records sha256 {}, but the commitment hashes to {local}",
            receipt_path.display(),
            receipt.artifact_sha256
        );
    }
    println!(
        "anchor OK: root {} is in {} as entry {} (logIndex {})",
        receipt.root,
        url,
        receipt.uuid,
        entry["logIndex"].as_u64().unwrap_or(receipt.log_index)
    );
    Ok(())
}

async fn fetch_entry(rekor_url: &str, uuid: &str) -> Result<Value> {
    let url = format!("{rekor_url}{ENTRIES_PATH}/{uuid}");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("accept", "application/json")
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        bail!("Rekor lookup of {uuid} failed ({status}): {text}");
    }
    let body: Value = serde_json::from_str(&text).context("Rekor response is not valid JSON")?;
    body.as_object()
        .and_then(|m| m.get(uuid).or_else(|| m.values().next()))
        .cloned()
        .with_context(|| format!("Rekor returned no entry for {uuid}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    fn kp() -> Keypair {
        Keypair::generate().unwrap()
    }

    fn b64_decode(s: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(s).unwrap()
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn pem_round_trips() {
        let key = kp();
        let pem = public_key_pem(&key.signing.verifying_key()).unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let decoded = public_key_from_pem(&pem).unwrap();
        assert_eq!(decoded.to_bytes(), key.signing.verifying_key().to_bytes());
        assert_eq!(hex::encode(decoded.to_bytes()), key.public_hex());
    }

    #[test]
    fn proposed_entry_fields_are_correct() {
        let key = kp();
        let artifact = br#"{"root":"deadbeef","count":3}"#;
        let entry = proposed_entry(artifact, &key).unwrap();

        assert_eq!(entry["kind"], "hashedrekord");
        assert_eq!(entry["apiVersion"], "0.0.1");
        assert_eq!(entry["spec"]["data"]["hash"]["algorithm"], "sha256");
        assert_eq!(
            entry["spec"]["data"]["hash"]["value"].as_str().unwrap(),
            sha256_hex(artifact)
        );

        // The signature is over the artifact bytes and verifies under the
        // embedded PEM key, which is exactly what a Rekor verifier redoes.
        let sig_bytes: [u8; 64] =
            b64_decode(entry["spec"]["signature"]["content"].as_str().unwrap())
                .try_into()
                .unwrap();
        let pem = String::from_utf8(b64_decode(
            entry["spec"]["signature"]["publicKey"]["content"]
                .as_str()
                .unwrap(),
        ))
        .unwrap();
        let verifying = public_key_from_pem(&pem).unwrap();
        verifying
            .verify(artifact, &Signature::from_bytes(&sig_bytes))
            .unwrap();
        assert!(verifying
            .verify(
                b"a different commitment",
                &Signature::from_bytes(&sig_bytes)
            )
            .is_err());
    }

    #[test]
    fn dry_run_payload_is_json() {
        let key = kp();
        let entry = proposed_entry(b"{}", &key).unwrap();
        let printed = serde_json::to_string_pretty(&entry).unwrap();
        let reparsed: Value = serde_json::from_str(&printed).unwrap();
        assert_eq!(reparsed, entry);
    }

    #[test]
    fn artifact_hash_is_read_back_out_of_an_entry() {
        let key = kp();
        let artifact = b"commitment bytes";
        let proposed = proposed_entry(artifact, &key).unwrap();
        // Rekor echoes the canonicalized entry back base64-encoded in `body`.
        let entry = serde_json::json!({
            "body": base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&proposed).unwrap()),
            "logIndex": 12345,
            "integratedTime": 1700000000u64,
        });
        assert_eq!(
            artifact_hash_from_entry(&entry).unwrap(),
            sha256_hex(artifact)
        );
        assert!(artifact_hash_from_entry(&serde_json::json!({"body": "!!not base64"})).is_err());
        assert!(artifact_hash_from_entry(&serde_json::json!({})).is_err());
    }

    #[test]
    fn receipt_sits_beside_its_commitment() {
        let path = anchor_path(Path::new("witness-data/commitments/1757-42.json"));
        assert_eq!(
            path,
            PathBuf::from("witness-data/commitments/1757-42.anchor.json")
        );
        // Receipts must not be mistaken for commitments by `latest_commitment`.
        assert!(path.to_str().unwrap().ends_with(".anchor.json"));
    }

    #[test]
    fn receipt_round_trips_through_json() {
        let record = AnchorRecord {
            rekor_url: REKOR_URL.into(),
            uuid: "24296fb24b8ad77a".into(),
            log_index: 7,
            integrated_time: Some(1_700_000_000),
            artifact_sha256: sha256_hex(b"{}"),
            root: "ab".repeat(32),
            signer: kp().public_hex(),
            ts_ms: 1,
        };
        let encoded = serde_json::to_vec(&record).unwrap();
        let decoded: AnchorRecord = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.uuid, record.uuid);
        assert_eq!(decoded.artifact_sha256, record.artifact_sha256);
        assert_eq!(decoded.log_index, 7);
    }
}
