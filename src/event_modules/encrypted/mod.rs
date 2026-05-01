//! `encrypted` event module — opaque ciphertext envelope around an inner event.
//!
//! Per-file layout (plan.md per-file rule): `codec.rs` owns encode/parse +
//! registry meta; `projector.rs` owns the (no-op) projector entry.

pub mod projector;
pub mod codec;
pub mod decrypt;

pub use projector::project_pure;
pub use codec::{
    encode_encrypted, outer_inner_type_code, parse_encrypted, EncryptedEvent, ENCRYPTED_META,
};
pub use decrypt::{decrypt_encrypted, DecryptOutcome, DecryptedInner};
