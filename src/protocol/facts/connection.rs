//! Connection handshake fact modules.
//!
//! Connection facts turn invite or endpoint context into an encrypted transport
//! relationship. A local endpoint emits an ephemeral secret and request; a peer
//! projects that request after matching invite/provenance context; responses
//! complete the handshake and seed sync.
//!
//! The handshake is deliberately fact-driven. Projectors wait through context
//! needs instead of calling directly into identity, transport, or sync code.
//! When enough context exists, they materialize connection rows and emit intents
//! such as response creation or sync seeding.
//!
//! Change these modules for request/response layout, connection-row
//! materialization, or handshake admission rules. Change transport intent
//! modules when established connections send or receive frame bytes.

pub mod ephemeral_secret;
pub mod request;
pub mod response;
