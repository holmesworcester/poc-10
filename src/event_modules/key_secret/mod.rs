//! `key_secret` event module — local-only AES-256 key material event.
//!
//! Per-file layout (plan.md per-file rule): `codec.rs` owns encode/parse,
//! deterministic event-id helpers, and registry meta; `projector.rs` owns
//! `ensure_schema` + the pure projector.

pub mod projector;
pub mod codec;

pub use projector::{ensure_schema, project_pure};
pub use codec::{
    deterministic_key_secret_created_at_ms, deterministic_key_secret_event,
    deterministic_key_secret_event_id, encode_key_secret, parse_key_secret, KeySecretEvent,
    KEY_SECRET_FIELDS, KEY_SECRET_META, KEY_SECRET_WIRE_SIZE,
};
