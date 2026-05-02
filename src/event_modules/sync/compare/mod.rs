//! `sync::compare` event module.
//!
//! Negentropy compare-this-node hint scoped to `(connection_id, workspace_id,
//! node_id)`. Replaces what Phase 8 called `connection::negentropy`.
//!
//! Wire-only / endpoint-local: per `plan.md` lines 365-369 these messages are
//! authenticated by the surrounding connection wrap, not by an event-graph
//! signature.

pub mod codec;
pub mod event;
pub mod projector;
pub mod registry_meta;

pub use codec::{encode, parse, CompareWireError};
pub use event::{CompareEvent, COMPARE_TYPE_CODE};
pub use projector::{compute_writes, ensure_schema, project};
pub use registry_meta::{project_pure, COMPARE_META};
