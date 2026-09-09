//! Content-addressed store: git-style flat files under objects/<2 hex>/<hash>.
//! Objects are immutable; writing is idempotent (same content, same path).

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::hash::blake3_hex;

#[derive(Clone)]
pub struct Cas {
    root: PathBuf,
}

impl Cas {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let root = data_dir.join("objects");
        fs::create_dir_all(&root).context("creating objects dir")?;
        Ok(Self { root })
    }

    fn path_for(&self, hash: &str) -> PathBuf {
        self.root.join(&hash[..2]).join(hash)
    }

    /// Store bytes, return their hash. No-op if the object already exists.
    pub fn put(&self, data: &[u8]) -> Result<String> {
        let hash = blake3_hex(data);
        let path = self.path_for(&hash);
        if !path.exists() {
            fs::create_dir_all(path.parent().unwrap())?;
            // Write to a temp file then rename so readers never see partial objects.
            let tmp = path.with_extension("tmp");
            fs::write(&tmp, data)?;
            fs::rename(&tmp, &path)?;
        }
        Ok(hash)
    }

    pub fn get(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        if hash.len() < 3 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("invalid object hash: {hash}");
        }
        let path = self.path_for(hash);
        match fs::read(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn has(&self, hash: &str) -> bool {
        hash.len() >= 3 && self.path_for(hash).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrip() {
        let dir = std::env::temp_dir().join(format!("witness-cas-{}", std::process::id()));
        let cas = Cas::open(&dir).unwrap();
        let h = cas.put(b"hello").unwrap();
        assert_eq!(cas.get(&h).unwrap().unwrap(), b"hello");
        assert!(cas.has(&h));
        assert!(cas.get(&"ab".repeat(32)).unwrap().is_none());
        fs::remove_dir_all(&dir).ok();
    }
}
