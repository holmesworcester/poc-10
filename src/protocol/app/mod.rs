//! CLI adapter for the current protocol.
//!
//! This module is intentionally the outer shell: Crux update logic, effect
//! descriptions, effect interpretation, and command summaries. Protocol facts,
//! codecs, projectors, queues, and table definitions stay in event modules.
//!
//! File purposes:
//! - `crux_app.rs`: message update and model/view bookkeeping.
//! - `flows.rs`: CLI flow orchestration expressed as Crux effects.
//! - `effects.rs`: typed shell requests and replies.
//! - `shell.rs`: real CLI shell state plus generic effect dispatch.
//! - `store_effects.rs`: store/protocol effect interpretation.
//! - `network_effects.rs`: TCP effect interpretation.
//! - `model.rs` and `summaries.rs`: app state and printable outputs.
//! - `flow_tests.rs`: shell-level flow tests; module scenarios belong beside
//!   the relevant event modules.

mod crux_app;
mod effects;
#[cfg(test)]
mod flow_tests;
mod flows;
mod model;
mod network_effects;
mod shell;
mod store_effects;
mod summaries;

pub use crux_app::ProtocolApp;
pub use effects::{
    ConnectionRequest, DrainReadyReport, FrameIngest, GeneratedContent, NetworkOp, NetworkReply,
    OutboundSyncWork, ProtocolEffect, StdoutOp, StdoutReply, StoreOp, StoreReply, SyncRoutesStart,
};
pub use model::{ProtocolModel, ProtocolMsg, ProtocolView};
pub use shell::{
    run_connect, run_count, run_generate, run_generate_dependent_events, run_invite,
    run_replay_dependent_events_reverse, run_serve, run_sync_routes,
};
pub use summaries::{
    ConnectSummary, CountSummary, DependentReplaySummary, DependentStageSummary, GenerateSummary,
    ServeSummary, StreamSummary, SyncSummary,
};
