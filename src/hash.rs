//! Content hashing. Cache keys and journal hashes are BLAKE3 over a
//! canonical form so the same logical request always maps to one object.

use serde_json::Value;

pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// serde_json's default Map is a BTreeMap, so re-serializing a parsed Value
/// yields sorted keys — that plus compact separators is our canonical JSON.
pub fn canonical_json(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("Value serialization cannot fail")
}

/// Cache/identity key for a proxied request: method + path + canonical body.
/// Non-JSON bodies are hashed as raw bytes.
pub fn request_key(method: &str, path: &str, body: &[u8]) -> String {
    let body_part: Vec<u8> = match serde_json::from_slice::<Value>(body) {
        Ok(v) => canonical_json(&v),
        Err(_) => body.to_vec(),
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(method.as_bytes());
    hasher.update(b"\n");
    hasher.update(path.as_bytes());
    hasher.update(b"\n");
    hasher.update(&body_part);
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ignores_json_key_order_and_whitespace() {
        let a = request_key("POST", "/v1/messages", br#"{"b":1,"a":2}"#);
        let b = request_key("POST", "/v1/messages", br#"{ "a": 2, "b": 1 }"#);
        assert_eq!(a, b);
    }

    #[test]
    fn key_distinguishes_path_and_body() {
        let a = request_key("POST", "/v1/messages", b"{}");
        let b = request_key("POST", "/v1/complete", b"{}");
        let c = request_key("POST", "/v1/messages", br#"{"x":1}"#);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
