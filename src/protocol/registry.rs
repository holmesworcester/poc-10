//! Concrete protocol description exported to core.
//!
//! This is the one place that assembles the match protocol as an executable
//! application: runtime declarations, daemon tick, and command table. The
//! binary selects this description; core consumes it generically.

use crate::core::app::{DaemonDescription, ProtocolDescription};
use crate::protocol::commands::{MatchCliContext, MATCH_COMMANDS};
use crate::protocol::runtime::{match_daemon_tick, MATCH_RUNTIME};

pub const MATCH_PROTOCOL: ProtocolDescription<MatchCliContext> = ProtocolDescription {
    name: "match",
    runtime: MATCH_RUNTIME,
    daemon: DaemonDescription {
        tick: match_daemon_tick,
    },
    commands: MATCH_COMMANDS,
    context: MatchCliContext::new,
};
