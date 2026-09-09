//! Merkle tree over journal record hashes. A published root commits the
//! operator to the full journal at a point in time; inclusion proofs let a
//! third party check "record N is in the committed run" without seeing the
//! rest, and (with the verified hash chain) that the journal wasn't rewritten.
//!
//! Construction: leaves are the 32-byte record hashes; parents are
//! blake3(left || right); an odd node is promoted unchanged.

use serde::{Deserialize, Serialize};

fn parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

pub fn root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                if pair.len() == 2 {
                    parent(&pair[0], &pair[1])
                } else {
                    pair[0]
                }
            })
            .collect();
    }
    Some(level[0])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    /// Sibling hash, hex.
    pub sibling: String,
    /// True if the sibling sits to the left of the running hash.
    pub sibling_is_left: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf: String,
    pub index: usize,
    pub count: usize,
    pub root: String,
    pub path: Vec<ProofStep>,
}

pub fn prove(leaves: &[[u8; 32]], index: usize) -> Option<InclusionProof> {
    if index >= leaves.len() {
        return None;
    }
    let mut path = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut pos = index;
    while level.len() > 1 {
        let sibling_pos = if pos.is_multiple_of(2) {
            pos + 1
        } else {
            pos - 1
        };
        if sibling_pos < level.len() {
            path.push(ProofStep {
                sibling: hex::encode(level[sibling_pos]),
                sibling_is_left: sibling_pos < pos,
            });
        }
        level = level
            .chunks(2)
            .map(|pair| {
                if pair.len() == 2 {
                    parent(&pair[0], &pair[1])
                } else {
                    pair[0]
                }
            })
            .collect();
        pos /= 2;
    }
    Some(InclusionProof {
        leaf: hex::encode(leaves[index]),
        index,
        count: leaves.len(),
        root: hex::encode(level[0]),
        path,
    })
}

pub fn verify(proof: &InclusionProof) -> bool {
    let mut current = match decode32(&proof.leaf) {
        Some(h) => h,
        None => return false,
    };
    for step in &proof.path {
        let sibling = match decode32(&step.sibling) {
            Some(h) => h,
            None => return false,
        };
        current = if step.sibling_is_left {
            parent(&sibling, &current)
        } else {
            parent(&current, &sibling)
        };
    }
    hex::encode(current) == proof.root
}

fn decode32(hex_str: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| *blake3::hash(format!("leaf{i}").as_bytes()).as_bytes())
            .collect()
    }

    #[test]
    fn proofs_verify_for_every_index_and_size() {
        for n in 1..=17 {
            let ls = leaves(n);
            let r = root(&ls).unwrap();
            for i in 0..n {
                let proof = prove(&ls, i).unwrap();
                assert_eq!(proof.root, hex::encode(r), "n={n} i={i}");
                assert!(verify(&proof), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn wrong_leaf_fails() {
        let ls = leaves(8);
        let mut proof = prove(&ls, 3).unwrap();
        proof.leaf = hex::encode(blake3::hash(b"forged").as_bytes());
        assert!(!verify(&proof));
    }
}
