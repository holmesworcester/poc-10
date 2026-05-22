//! Connection intent modules.
//!
//! Connection intents are delayed handshake work. Projection emits them when a
//! request has enough context to answer or when an invite/server bootstrap
//! should send a request over transport. The leaf handlers load exact facts and
//! return `PipelineEffects`; they should not duplicate request/response
//! admission policy from connection projectors.

pub mod create_response;
pub mod send_bootstrap_request;
