//! `self_address` event module.
//!
//! Endpoint's own claimed address. Used as a dialing hint and as input to
//! `connection.wrap_bootstrap` lookups.
//!
//! Translated from poc-6 `events/network/self_address.py` per `plan.md`
//! lines 204-218.

pub mod event;
pub mod projector;
pub mod registry_meta;
pub mod codec;

pub use event::{SelfAddressEvent, SELF_ADDRESS_TYPE_CODE};
pub use projector::{ensure_schema, project};
pub use registry_meta::{project_pure, SELF_ADDRESS_META};
pub use codec::{encode, parse, SelfAddressWireError, SELF_ADDRESS_WIRE_SIZE};
