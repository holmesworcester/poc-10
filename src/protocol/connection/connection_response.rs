//! Membership connection response family.
//!
//! A response completes a membership handshake and is the local connection
//! fact: its fact id is the connection id and its body carries the
//! `connection_secret`. It writes the shared connection row (the same table
//! bootstrap connections use, keyed by connection id) so established frames and
//! sync treat both connection kinds identically, and publishes the
//! `connection_response` context other modules rely on. The secret is derived
//! from Diffie-Hellman only; no invite material is involved.
//!
//! The family is split by pipeline stage: `encode`/`decode` (wire bytes ⟷ typed
//! value), `create` (the Diffie-Hellman key schedule and canonical construction),
//! `authenticate` (decode + id + intrinsic fields), `adapt` (identity), and
//! `project` (admission + materialization). Sealing a response for the wire is the
//! connection transport layer (`connection_handshake_wire`), not this family: the response
//! is sealed onto the wire and opened on arrival exactly like an established
//! frame, then admitted here as a durable plaintext fact.

pub mod adapt;
pub mod authenticate;
pub mod create;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;

pub use decode::decode_fact_payload;
pub(crate) use decode::Codec;
