//! Negentropy-tree state helpers.
//!
//! Shared types and the domain-separated keyed hash function used by the
//! incremental maintenance routine. Per `plan.md` lines 343-364:
//!
//! - `Hset("root", R_v)` is XORed across roots in `v`.
//! - `Hset("dep", X_v ∩ P)` is XORed across deps required by roots in `v`
//!   that are present locally, with refcount-gated 0→1 / 1→0 transitions
//!   to prevent double-counting under duplicate edges.
//!
//! We use BLAKE3 keyed-hash for the per-event contribution. XOR over a fixed
//! 32-byte digest is symmetric, so add/remove are the same operation; the
//! refcount machinery is what stops duplicate edges from XOR-cancelling.
//!
//! Domain separation:
//! - root domain: BLAKE3 keyed-hash with the literal "poc8-negentropy-root-v1"
//! - dep domain:  BLAKE3 keyed-hash with the literal "poc8-negentropy-dep-v1"
//!
//! 32-byte literal keys are chosen so each domain's hash is a different
//! function from the same event id.

/// Per-domain 32-byte BLAKE3 key. Padded with zeros so the literal stays
/// readable in the source.
pub fn root_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    let label = b"poc8-negentropy-root-v1";
    k[..label.len()].copy_from_slice(label);
    k
}

pub fn dep_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    let label = b"poc8-negentropy-dep-v1";
    k[..label.len()].copy_from_slice(label);
    k
}

/// Hash one event id under the root domain.
pub fn h_root(event_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(&root_key());
    hasher.update(event_id);
    let out = hasher.finalize();
    *out.as_bytes()
}

/// Hash one event id under the dep domain.
pub fn h_dep(event_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(&dep_key());
    hasher.update(event_id);
    let out = hasher.finalize();
    *out.as_bytes()
}

/// XOR a 32-byte contribution into an accumulator. Symmetric: add and
/// remove are the same operation.
pub fn xor_into(acc: &mut [u8; 32], contribution: &[u8; 32]) {
    for i in 0..32 {
        acc[i] ^= contribution[i];
    }
}
