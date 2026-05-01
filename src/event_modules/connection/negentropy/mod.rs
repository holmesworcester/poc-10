//! `negentropy` event module.
//!
//! Sync-compare event keyed `(connection_id, workspace_id)`. Wire-only:
//! these messages are endpoint-local sync hints, not durable shared events
//! (see `plan.md` lines 292-300). They go through parse + project so the
//! pipeline applies dedupe-by-wire-id; the projector emits subsequent
//! intents (have/need/send) but writes no durable state row.
//!
//! Translated from poc-6 `events/network/negentropy.py` per `plan.md`
//! lines 204-218.

pub mod event;
pub mod projector;
pub mod registry_meta;
pub mod codec;

pub use event::{NegentropyEvent, NEGENTROPY_TYPE_CODE};
pub use projector::project;
pub use registry_meta::{project_pure, NEGENTROPY_META};
pub use codec::{encode, parse, NegentropyWireError};
