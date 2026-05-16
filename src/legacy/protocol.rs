//! Legacy protocol compatibility surface.
//!
//! The target architecture should not add new behavior here. This module keeps
//! the old poc-8 production path reachable while the `match` app is cut over to
//! target facts, projectors, context matchers, and handlers. When the target
//! runtime facade owns store opening, command dispatch, projection drain, and
//! handler dispatch, this module should disappear rather than become a wrapper
//! around the new model.

pub mod assembly;
pub mod commands;
pub mod event_modules;
pub mod wire;

pub use assembly::{schemas, Protocol};
