//! Connection handshake scope: fact and intent modules.
//!
//! Connection facts turn invite or endpoint context into an encrypted transport
//! relationship. A local endpoint emits an ephemeral secret and request; a peer
//! projects that request after matching invite and fact-receipt context;
//! responses complete the handshake and seed sync.
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
pub mod fact_receipt;
pub mod request;
pub mod response;

// Intents: delayed handshake work. Projection emits these when a request has
// enough context to answer or when an invite/server bootstrap should send a
// request over transport.
pub mod create_response;
pub mod send_bootstrap_request;
