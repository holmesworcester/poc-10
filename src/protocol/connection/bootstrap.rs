//! Bootstrap connection-frame family.
//!
//! Bootstrap frames are the network-only wrappers that carry canonical
//! `connection::request` and `connection::response` facts before an
//! established connection secret exists. Their public headers identify the
//! intended endpoint and ephemeral public key needed for the bootstrap DH, and
//! their bodies carry the canonical fact bytes under AEAD authentication.

pub mod create;
pub mod layout;

pub use layout::{
    open_connection_request, open_connection_response, seal_connection_request,
    seal_connection_response, SEALED_CONNECTION_REQUEST_BYTES, SEALED_CONNECTION_RESPONSE_BYTES,
    TYPE_SEALED_CONNECTION_REQUEST, TYPE_SEALED_CONNECTION_RESPONSE,
};
