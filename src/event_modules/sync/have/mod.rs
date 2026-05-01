//! `sync::have` event module.
//!
//! "I have this id" hint emitted when a leaf compare detects a remote-claimed
//! id we may need (plan.md lines 308-316). Endpoint-local; no signature.

pub mod codec;
pub mod event;
pub mod projector;
pub mod registry_meta;

pub use codec::{encode, parse, HaveWireError};
pub use event::{HaveEvent, HAVE_TYPE_CODE};
pub use projector::{ensure_schema, project};
pub use registry_meta::{project_pure, HAVE_META};
