//! `connection_prekey` event module.
//!
//! Per-endpoint long-lived asymmetric prekey kept *secret* by its owner. The
//! event carries both the private and public halves; only the owner endpoint
//! holds it, so it never leaves the local DB. The shared (broadcast) half is
//! `connection_prekey_shared`.
//!
//! Translated from poc-6 `events/network/connection_prekey.py` per
//! `plan.md` lines 204-218.

pub mod event;
pub mod projector;
pub mod registry_meta;
pub mod codec;

pub use event::{ConnectionPrekeyEvent, CONNECTION_PREKEY_TYPE_CODE};
pub use projector::{ensure_schema, project};
pub use registry_meta::{project_pure, CONNECTION_PREKEY_META};
pub use codec::{encode, parse, ConnectionPrekeyWireError, CONNECTION_PREKEY_WIRE_SIZE};
