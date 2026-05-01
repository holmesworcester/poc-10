//! Projector context: strict `{event, deps, labels}` contract.
//!
//! Per plan.md (commit afc171015718e9a1e), the strict context contract for
//! projectors is `{event, deps, labels}` and nothing else. The legacy
//! per-event-type loaders that used to live behind a `ProjectionQueries`
//! trait (and dispatched through `EventTypeMeta::context_loader`) have
//! been retired — every projector now consumes the snapshot produced
//! by [`crate::state::generic_context::load_generic_context`].
//!
//! This module is intentionally empty. The `ProjectionQueries` trait,
//! its per-event-type `load_*_context` methods, and the
//! `define_query_context_loader!` macro have all been removed. The
//! file is retained only so existing `mod queries;` declarations and
//! `crate::projection::queries` paths continue to resolve while the
//! retirement settles. Future cleanup may delete the file outright.
