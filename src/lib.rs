//! witness — a provenance-native caching proxy for model APIs.
//!
//! Composes two protocols:
//! - Pact: Ed25519 agent identity + narrowing-only delegation chains,
//!   verified locally at the proxy boundary.
//! - AgentReplay: content-addressed recording of every call in a
//!   hash-chained journal, with deterministic replay and Merkle commitments.

pub mod cas;
pub mod client;
pub mod hash;
pub mod identity;
pub mod journal;
pub mod mcp;
pub mod merkle;
pub mod mock;
pub mod proxy;
