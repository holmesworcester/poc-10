//! Outbound network-send handler.
//!
//! Owns the deferred intent that asks the runtime to push an already-packaged
//! transit frame onto a connection's TCP socket. The actual socket write is
//! not yet wired here — the driver validates the frame envelope shape and
//! advances a per-connection frame-level idempotence cursor fact so duplicate
//! submissions of the same frame collapse to a single send.

pub mod driver;
pub mod intent;

pub use driver::*;
pub use intent::*;
