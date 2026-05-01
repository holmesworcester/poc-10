//! # OutboundFrame (capability-typed transit payload)
//!
//! ## Purpose
//! An [`OutboundFrame`] is the only payload [`super::send`] accepts. The
//! whole point of the type is that owning one is a *capability proof*:
//! you could only have minted it by going through one of the connection
//! module's wrap functions, which have already done the workspace-membership
//! check.
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the wrapped, transit-ready ciphertext bytes,
//! - a `pub(crate)` constructor available only inside this crate.
//!
//! Does NOT own:
//! - the wire layout (lives in `event_modules::connection::wrap`),
//! - the cryptography (lives in `event_modules::connection::secrets`),
//! - any framing — that's transport's job (`[u32 len][bytes]`).
//!
//! ## Interfaces
//! - [`OutboundFrame::as_bytes`] — borrow for transmission.
//! - [`OutboundFrame::into_bytes`] — consume into the underlying `Vec`.
//! - [`OutboundFrame::len`] / [`OutboundFrame::is_empty`].
//! - `pub(crate) OutboundFrame::from_bytes` — sole constructor.
//! - `#[cfg(test)] OutboundFrame::for_test_only` — escape hatch.
//!
//! ## State
//! Single-field newtype around `Vec<u8>`.
//!
//! ## Invariants
//! - **No path other than `event_modules::connection::wrap` and
//!   `event_modules::connection::wrap_bootstrap` may mint an
//!   [`OutboundFrame`].** Both of those call into
//!   `OutboundFrame::from_bytes` below.
//! - The constructor is `pub(crate)`. Modules in other crates (or future
//!   workspace splits) cannot mint frames.
//! - Do not add a `pub` constructor, `From<Vec<u8>>`, or `Default`. If you
//!   need one, you're either:
//!   1. fuzzing / testing — use `OutboundFrame::for_test_only(...)`;
//!   2. a new wrap path — add it inside
//!      `event_modules::connection::wrap` so the workspace check still
//!      happens; or
//!   3. wrong.
//!
//! ## Flow
//! ```text
//!   wrap()/wrap_bootstrap() --pub(crate) from_bytes--> OutboundFrame
//!                                                          |
//!                                              transport_v2::send --> TCP
//! ```
//!
//! ## Failure / restart behavior
//! Pure value type. No state to recover.
//!
//! ## Performance notes
//! Holds a single `Vec<u8>`. `into_bytes` lets the transport hand the
//! buffer to the socket without copying.
//!
//! ## Testing hooks
//! - `for_test_only` synthesizes frames in unit tests without going through
//!   the full wrap path. Not callable from non-test code.

/// A wrapped, transit-ready ciphertext. Hand to `transport_v2::send`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundFrame {
    bytes: Vec<u8>,
}

impl OutboundFrame {
    /// Crate-private constructor. Only the `connection` module's wrap
    /// functions may call this. Documented as such — see the module-level
    /// invariant above.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the inner ciphertext for transmission.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Move out the inner ciphertext (consuming the frame). Used by the TCP
    /// send path.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Test-only escape hatch. Available only under `cfg(test)` so unit tests
    /// can synthesize frames without going through the full wrap path. Do
    /// not call from non-test code.
    #[cfg(test)]
    pub fn for_test_only(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}
