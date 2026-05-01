//! `connection_prekey_shared` event module.
//!
//! Per-endpoint long-lived asymmetric prekey *broadcast* to peers. Carries
//! only the public half. Used by `connection.wrap_bootstrap` to seal the
//! bootstrap connection_request.
//!
//! Translated from poc-6 `events/network/connection_prekey_shared.py` per
//! `plan.md` lines 204-218.

pub mod event;
pub mod projector;
pub mod registry_meta;
pub mod codec;

pub use event::{ConnectionPrekeySharedEvent, CONNECTION_PREKEY_SHARED_TYPE_CODE};
pub use projector::{ensure_schema, project};
pub use registry_meta::{project_pure, CONNECTION_PREKEY_SHARED_META};
pub use codec::{encode, parse, ConnectionPrekeySharedWireError, CONNECTION_PREKEY_SHARED_WIRE_SIZE};
