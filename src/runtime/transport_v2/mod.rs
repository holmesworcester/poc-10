//! # Transport v2 (TCP byte I/O)
//!
//! ## Purpose
//! A minimal byte-pipe between two `endpoint_id`s. It moves opaque
//! [`OutboundFrame`]s from a sender to a receiver and produces opaque
//! `InboundDelivery`s from receiver back to the runtime. It produces and
//! interprets no bytes of its own (`plan.md` line 119).
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the listener bound on the daemon's `endpoint_id`,
//! - the socket cache `(local_endpoint_id, remote_endpoint_id) -> TcpStream`,
//! - `[u32 length][bytes]` framing on the wire,
//! - egress ([`send`]) and ingress ([`accept_loop`]) entrypoints,
//! - the [`AddressBook`] / [`AddressResolver`] surface for endpoint-id →
//!   `SocketAddr` resolution.
//!
//! Does NOT own:
//! - any cryptography, key derivation, or auth — those live in
//!   `event_modules::connection::wrap`,
//! - workspace membership checks — done at wrap time,
//! - frame minting — only `event_modules::connection::wrap{,_bootstrap}`
//!   may construct an [`OutboundFrame`] (see [`outbound_frame`]),
//! - retry / backoff policy — that's the caller's job.
//!
//! ## Interfaces
//! - [`accept_loop`] — bind a listener and stream `InboundDelivery`s to a
//!   channel.
//! - [`send`] — write an [`OutboundFrame`] to the connection identified by
//!   `(local_endpoint_id, remote_endpoint_id)`.
//! - [`SocketCache`] — pooled `TcpStream`s, keyed by endpoint pair.
//! - [`AddressBook`] / [`AddressResolver`] — pluggable endpoint → addr
//!   resolution.
//! - [`OutboundFrame`] — capability-typed transit payload.
//!
//! ## State
//! - `SocketCache` (in-memory `HashMap<(EndpointId, EndpointId), TcpStream>`),
//! - listener task, ingress channel sender,
//! - `AddressBook` `HashMap<EndpointId, SocketAddr>`.
//!
//! ## Invariants
//! - "If you can call `send` you are holding an [`OutboundFrame`] minted by
//!   `connection.wrap` or `connection.wrap_bootstrap`." This is enforced by
//!   the `pub(crate)` constructor on [`OutboundFrame`].
//! - Wire framing is `[u32 BE length][bytes]`. Length covers only the
//!   payload bytes.
//! - No TLS, no QUIC, no UDP. Pure tokio TCP.
//!
//! ## Flow
//! ```text
//!   Egress:
//!     OutboundFrame --send(local, remote)--> SocketCache.get --> TcpStream
//!                                                     |
//!                                          [u32 len][bytes] write
//!
//!   Ingress:
//!     listener --accept--> spawn read task --> [u32 len][bytes] read loop
//!                                                     |
//!                                            InboundDelivery -> mpsc
//! ```
//!
//! ## Failure / restart behavior
//! - On `send` failure the cached stream is dropped; next `send` re-resolves
//!   and reconnects. Backoff is the caller's responsibility (the
//!   `OutboxWake` handler schedules a retry via `StepResult.queue_writes`).
//! - On listener crash, restart re-binds the same `endpoint_id`; in-flight
//!   frames are lost and rely on inbound dedupe (`inbound_bytes.wire_id`)
//!   for idempotency.
//!
//! ## Performance notes
//! - One `TcpStream` per endpoint pair, kept warm by the cache.
//! - Length-prefix framing avoids per-byte parsing on ingress.
//! - Phase 1 keeps the existing QUIC `runtime/transport` in tree alongside;
//!   cutover happens later.
//!
//! ## Testing hooks
//! - `tests/transport_v2_*.rs` for end-to-end TCP round-trips.
//! - In-crate tests in `tcp.rs` use `127.0.0.1:0` ephemeral binds.

pub mod addrs;
pub mod outbound_frame;
pub mod tcp;

pub use addrs::{AddressBook, AddressResolver};
pub use outbound_frame::OutboundFrame;
pub use tcp::{accept_loop, send, InboundDelivery, SocketCache, TransportError};
