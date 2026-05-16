//! Shared event-pipeline worker machinery.
//!
//! Event admission/projection mechanics stay in `event_pipeline` because they
//! are still cross-cutting pipeline behavior. Generic lifecycle writes and
//! local retention cleanup live under invariant-specific worker files instead
//! of this namespace.

pub mod event_pipeline;
