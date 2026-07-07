//! Membership connection request family.
//!
//! A membership connection request is first contact with an endpoint that
//! already knows us: it is authorized by `endpoint_shared` membership, not an
//! invite. The fact is a durable plaintext record like every other fact —
//! `connection_response` joins against it by id. The family is split by pipeline
//! stage: `encode`/`decode` (wire bytes ⟷ typed value plus the endpoint signing
//! transcript), `author` (pure local construction) and `commands` (the runtime
//! entry that authors), `authenticate` (decode + id + endpoint-signature park),
//! `adapt` (identity), and `project` (admission + materialization).
//!
//! Sealing a request for the wire is the connection transport layer
//! (`connection_handshake_wire`), not this family: a request fact is sealed onto the wire
//! and opened on arrival exactly like an established frame, then admitted here as
//! a durable plaintext fact. This family carries no invite material. Response
//! creation, frame sending, and socket IO belong to the downstream connection
//! modules.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod commands;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;
pub mod rows;

pub use project::{
    connection_request_need, connection_request_offer, connection_response_for_request_need,
    connection_response_for_request_offer,
};

pub use decode::decode_fact_payload;
pub(crate) use decode::Codec;
