//! Product-facing `match` binary entrypoint.
//!
//! The binary chooses the concrete protocol description. Core does the generic
//! CLI/daemon plumbing from that description; protocol modules own the actual
//! commands, projector registry, context keys, and intent handlers.

pub fn run(argv: Vec<String>) -> Result<(), String> {
    crate::core::app::run(&crate::protocol::app::MATCH_PROTOCOL, argv)
}
