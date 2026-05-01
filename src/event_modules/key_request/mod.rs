//! `key_request` event module — request for a wrapped content-key delivery.
//!
//! Per-file layout (plan.md per-file rule): `codec.rs` owns encode/parse,
//! deterministic helpers, the `delivery_target_id` derivation (consumed by
//! `key_shared`), and the registry meta. `projector.rs` owns
//! `ensure_schema` + the pure projector.
//!
//! TODO(plan.md Wave 2): Wave-1 deferred drop — entangled with identity /
//! transport. Migrated to per-file layout per the plan anyway since the
//! event still exists.

pub mod projector;
pub mod codec;

pub use projector::{ensure_schema, project_pure};
pub use codec::{
    delivery_target_id, deterministic_key_request_created_at_ms, encode_key_request,
    parse_key_request, KeyRequestEvent, KEY_REQUEST_FIELDS, KEY_REQUEST_META,
    KEY_REQUEST_WIRE_SIZE,
};
