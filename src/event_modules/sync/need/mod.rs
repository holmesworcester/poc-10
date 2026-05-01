//! `sync::need` event module.
//!
//! "I need this id, please send the actual event" hint. When local has
//! `event_id`, the projector writes `outbox(connection_id, event_id)` so the
//! send-path picks up the durable event bytes (plan.md line 379). Endpoint-
//! local; no signature.

pub mod codec;
pub mod event;
pub mod projector;
pub mod registry_meta;

pub use codec::{encode, parse, NeedWireError};
pub use event::{NeedEvent, NEED_TYPE_CODE};
pub use projector::{ensure_schema, project};
pub use registry_meta::{project_pure, NEED_META};
