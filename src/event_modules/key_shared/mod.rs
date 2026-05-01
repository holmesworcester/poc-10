//! `key_shared` event module — wrapped content-key delivery, frontier-anchored.
//!
//! Per-file layout (plan.md per-file rule): `codec.rs` owns encode/parse +
//! registry meta; `projector.rs` owns `ensure_schema`, the
//! projector-context loader, and the pure projector.

pub mod projector;
pub mod codec;

pub use projector::{ensure_schema, project_pure};
pub use codec::{
    encode_key_shared, parse_key_shared, KeySharedEvent, KEY_SHARED_FIELDS, KEY_SHARED_META,
    KEY_SHARED_WIRE_SIZE,
};
