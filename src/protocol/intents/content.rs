//! Content purge intent modules.
//!
//! Content intents perform delayed cleanup after projection has established
//! that a message, file, reaction, or retention range should disappear from
//! derived rows or stored facts. Projectors decide when purge work is valid;
//! handlers execute the specific purge in the common `PipelineEffects` commit
//! path.

pub mod purge_below_retention_floor;
pub mod purge_deleted_message;
pub mod purge_expired_message;
pub mod purge_message_child;
