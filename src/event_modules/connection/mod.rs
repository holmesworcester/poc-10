//! # Connection event family
//!
//! ## Purpose
//! The `connection` event family is the cryptographic + addressing layer
//! between two endpoints: prekey exchange, connection establishment, key
//! derivation, observed addresses, sync windows, and the
//! `wrap`/`unwrap` functions that mint and consume [`crate::runtime::transport_v2::OutboundFrame`]s
//! (`plan.md` lines 121-133, 204-218).
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the wire layout for connection-scoped events ([`event`],
//!   [`codec`], [`mod@wrap`]),
//! - connection secrets storage ([`secrets`]),
//! - the projector for `Connection` (and the table set
//!   `connections`, `connection_shared_workspaces`),
//! - per-event-type submodules: [`connection_prekey`],
//!   [`connection_prekey_shared`], [`intro`], [`observed_address`],
//!   [`self_address`], [`negentropy`], [`sync_window`].
//!
//! Does NOT own:
//! - byte transport — see [`crate::runtime::transport_v2`],
//! - the substrate dispatcher / queue — see
//!   [`crate::runtime::control_loop`],
//! - workspace membership — that's read by `wrap` from
//!   `connection_shared_workspaces` but *written* by workspace-scoped
//!   modules.
//! - `server_connection` — deferred to Wave 2 (cloud relay / always-on
//!   server endpoints).
//!
//! ## Interfaces
//! - [`wrap()`] / [`wrap_bootstrap()`] — the SOLE paths to mint an
//!   [`crate::runtime::transport_v2::OutboundFrame`]. Both perform the workspace-membership check.
//! - [`unwrap`] — symmetric receive-side check + decrypt.
//! - [`InnerCanonicalEvent`] — the `(workspace_id, bytes)` pair the wrap
//!   path consumes.
//! - [`UnwrapResult`] / [`UnwrapKind`] / [`UnwrapError`] / [`WrapError`]
//!   — chain-level outcomes.
//! - [`ensure_schema`] — registers all tables this family writes to.
//! - [`Connection`] / [`ConnectionEvent`] (alias) /
//!   [`ConnectionPrekey`] / [`ConnectionPrekeyShared`] — wire types.
//! - [`secrets::lookup_outbound`] / [`secrets::lookup_inbound`] /
//!   [`SecretRow`] — connection-secret table surface.
//! - Type-code constants: [`CONNECTION_TYPE_CODE`],
//!   [`CONNECTION_PREKEY_TYPE_CODE`],
//!   [`CONNECTION_PREKEY_SHARED_TYPE_CODE`].
//!
//! ## State
//! Tables created by [`ensure_schema`]:
//! - `connection_secrets` (outbound + inbound directions, TTLs),
//! - `connections` and `connection_shared_workspaces` (projector
//!   tables),
//! - `connection_prekey`, `connection_prekey_shared`, `intro`,
//!   `observed_address`, `self_address`. (`negentropy` and
//!   `sync_window` operate purely on canonical-event rows + projector
//!   side state.)
//!
//! ## Invariants
//! - **Two independent workspace-membership checks.** `wrap` enforces
//!   it before egress; `unwrap` enforces a symmetric check on the
//!   receive side.
//! - Only `wrap` and `wrap_bootstrap` may mint an [`crate::runtime::transport_v2::OutboundFrame`].
//!   The constructor on [`crate::runtime::transport_v2::OutboundFrame`] is `pub(crate)` and these
//!   are the only callers.
//! - `connection_id` is the canonical event id of the `Connection`
//!   event. Endpoint pair `(endpoint_a, endpoint_b)` is keyed inside
//!   the event payload.
//! - Connection-scoped events (this family) live at
//!   `EventScope::EndpointLocal`; durable workspace events live at
//!   `EventScope::Durable`.
//!
//! ## Flow
//! ```text
//!   Egress:
//!     projector --enqueue(conn, event_id)--> outbox row
//!     ConnectionSender drain --connection::wrap--> OutboundFrame
//!                                                 \
//!                                                  transport_v2::send --> TCP
//!
//!   Ingress:
//!     transport_v2 accept_loop --InboundDelivery--> control_loop
//!     control_loop inbound chain --connection::unwrap--> InnerCanonicalEvent[]
//!     per inner event: admit_event_id -> parse -> project -> apply
//! ```
//!
//! ## Failure / restart behavior
//! - `WrapError::NoOutboundSecret` → connection isn't ready; sender
//!   bails the whole drain.
//! - `UnwrapError::*` on inbound → `inbound_bytes.status = 'invalid'`;
//!   no inner events processed.
//! - Encrypted events whose key is missing block on the workspace key
//!   event id; standard `unblock_dependents` flow recovers when the
//!   key arrives.
//!
//! ## Performance notes
//! - Wrap performs one workspace-membership SELECT per call.
//! - Connection secrets are held in the SQLite-backed
//!   `connection_secrets` table; the wrap path is keyed by
//!   `connection_id` for outbound and by AEAD nonce on inbound.
//! - Wire payloads are length-prefixed inside the wrap envelope; the
//!   transport adds its own `[u32 len][bytes]` framing on top.
//!
//! ## Testing hooks
//! - In-tree tests under each submodule (`wrap.rs`, `unwrap.rs`,
//!   `secrets.rs`, etc.).
//! - Roundtrip tests under `tests/connection_wrap_*.rs` exercise the
//!   bootstrap + connection-secret modes.
//!
//! Phase 2 (this commit) added supporting connection-related event types
//! ported from poc-6 `events/network/`, translated to endpoint-pair scope
//! per `plan.md` lines 204-218.

pub mod event;
pub mod local_signing_key;
pub mod post_apply;
pub mod projector;
pub mod registry_meta;
pub mod secrets;
pub mod codec;
pub mod wrap;

// Phase 2 supporting event types.
pub mod connection_prekey;
pub mod connection_prekey_shared;
pub mod intro;
pub mod negentropy;
pub mod observed_address;
pub mod self_address;
pub mod sync_window;
// TODO(plan.md Wave 2): `server_connection` is deferred until cloud-relay /
// always-on server endpoints land. See plan.md line 216.

pub use event::{
    Connection, ConnectionPrekey, ConnectionPrekeyShared, CONNECTION_TYPE_CODE,
    CONNECTION_PREKEY_SHARED_TYPE_CODE, CONNECTION_PREKEY_TYPE_CODE,
};
pub use registry_meta::{project_pure, CONNECTION_META};

/// `Connection` is the wire-level type. Re-exported under the
/// `ConnectionEvent` name to match the `XxxEvent` naming used by the other
/// connection submodules and the `ParsedEvent::Connection(ConnectionEvent)`
/// variant.
pub type ConnectionEvent = Connection;
pub use secrets::{
    ensure_schema as ensure_secrets_schema, lookup_outbound, lookup_inbound,
    SecretDirection, SecretRow,
};
pub use wrap::{
    unwrap, wrap, wrap_bootstrap, InnerCanonicalEvent, UnwrapError, UnwrapKind, UnwrapResult,
    WrapError,
};

use rusqlite::Connection as SqlConnection;

pub fn ensure_schema(conn: &SqlConnection) -> rusqlite::Result<()> {
    secrets::ensure_schema(conn)?;
    // Top-level Connection projector tables (`connections`,
    // `connection_shared_workspaces`).
    projector::ensure_schema(conn)?;
    connection_prekey::ensure_schema(conn)?;
    connection_prekey_shared::ensure_schema(conn)?;
    intro::ensure_schema(conn)?;
    observed_address::ensure_schema(conn)?;
    self_address::ensure_schema(conn)?;
    Ok(())
}
