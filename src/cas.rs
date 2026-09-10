//! Content-addressed store: git-style flat files under objects/<2 hex>/<hash>.
//! Objects are immutable; writing is idempotent (same content, same path).

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hash::blake3_hex;

/// Distinguishes concurrent writers of the same object. Two writers of
/// identical content hash to the same final path, so the temp path must not
/// collide or one writer's rename leaves the other with a vanished file.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    /// Safe to call concurrently for identical content.
    pub fn put(&self, data: &[u8]) -> Result<String> {
        let hash = blake3_hex(data);
        let path = self.path_for(&hash);
        if !path.exists() {
            fs::create_dir_all(path.parent().unwrap())?;
            // Write to a per-writer temp file, then rename so readers never
            // see a partial object. rename(2) over an existing file is
            // atomic, so racing writers of identical content both succeed.
            let tmp = path.with_extension(format!(
                "tmp.{}.{}",
                std::process::id(),
                TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            if let Err(e) = fs::write(&tmp, data) {
                return Err(e).context("writing temp object");
            }
            if let Err(e) = fs::rename(&tmp, &path) {
                fs::remove_file(&tmp).ok();
                return Err(e).context("publishing object");
            }
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
    fn concurrent_identical_puts_all_succeed() {
        // Regression: all writers of the same content once shared one temp
        // path, so every writer but one failed under concurrency.
        let dir = std::env::temp_dir().join(format!("witness-cas-race-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let cas = Cas::open(&dir).unwrap();
        let handles: Vec<_> = (0..32)
            .map(|_| {
                let cas = cas.clone();
                std::thread::spawn(move || cas.put(b"the same bytes from every thread"))
            })
            .collect();
        for handle in handles {
            handle
                .join()
                .unwrap()
                .expect("concurrent put must not fail");
        }
        assert_eq!(
            cas.get(&blake3_hex(b"the same bytes from every thread"))
                .unwrap()
                .unwrap(),
            b"the same bytes from every thread"
        );
        // No temp files left behind.
        let leftovers: Vec<_> = walk(&dir)
            .into_iter()
            .filter(|p| p.to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    out.extend(walk(&path));
                } else {
                    out.push(path);
                }
            }
        }
        out
    }

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
