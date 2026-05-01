//! `observed_address` event module.
//!
//! Peer's observation of another endpoint's address. TTL-based: the
//! recipient drops stale observations.
//!
//! Translated from poc-6 `events/network/observed_address.py` per
//! `plan.md` lines 204-218.

pub mod event;
pub mod projector;
pub mod registry_meta;
pub mod codec;

pub use event::{ObservedAddressEvent, OBSERVED_ADDRESS_TYPE_CODE};
pub use projector::{ensure_schema, project};
pub use registry_meta::{project_pure, OBSERVED_ADDRESS_META};
pub use codec::{encode, parse, ObservedAddressWireError, OBSERVED_ADDRESS_WIRE_SIZE};
