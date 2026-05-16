//! Legacy compatibility island.
//!
//! Everything in this module is old production-path code retained only while
//! the `match` binary is being cut over to target facts, `WakeLoop`,
//! projectors, context matchers, and flat handlers. New architecture code
//! should not add modules here. Deleting `src/legacy/` is the intended final
//! cleanup once the target runtime facade owns the production path.

pub mod app;
pub mod daemon;
pub mod protocol;
pub mod round_robin;
pub mod workers;
