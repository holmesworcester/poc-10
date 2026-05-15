//! Sync CLI command registry.
//!
//! Manual finite sync serving is deprecated. Ongoing sync starts and responds
//! from the daemon's `sync_tick` worker.

use crate::core::commands::CliCommand;
use crate::protocol::commands::Context;

pub fn commands() -> Vec<CliCommand<Context>> {
    Vec::new()
}
