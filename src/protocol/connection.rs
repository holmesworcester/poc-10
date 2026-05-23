//! Connection protocol scope: handshake, receipt, and frame fact modules.
//!
//! Connection facts turn invite or endpoint context into an encrypted transport
//! relationship. A local endpoint emits an ephemeral secret and request; a peer
//! projects that request after matching invite and fact-receipt context;
//! responses complete the handshake and seed sync.
//! Established connections then carry encrypted `connection::frame` facts whose
//! projector opens the frame, validates receive context, and emits the child
//! facts admitted by the connection protocol.
//!
//! The handshake is deliberately fact-driven. Projectors wait through context
//! needs instead of calling directly into identity, transport, or sync code.
//! When enough context exists, they materialize connection rows and emit intents
//! such as response creation or sync seeding.
//!
//! Change these modules for request/response layout, connection-row
//! materialization, receipt policy, frame admission rules, or connection-frame
//! layout. Change transport intent modules when socket queues send or receive
//! already-classified connection bytes.

pub mod ephemeral_secret;
pub mod fact_receipt;
pub mod frame;
pub mod request;
pub mod response;

// Intents: delayed handshake work. Projection emits these when a request has
// enough context to answer or when an invite/server bootstrap should send a
// request over transport.
pub mod create_response;
pub mod send_bootstrap_request;
