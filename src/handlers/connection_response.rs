//! Target connection_response handler.
//!
//! Drives the responder side of the connection handshake: given a validated
//! inbound connection_request fact and the local responder material, produce
//! the canonical `connection_response` fact using the legacy native key
//! schedule (DH(eph_r, eph_i), DH(static_r, eph_i), invite bootstrap secret,
//! transcript-bound HKDF). The fact is then admitted through the usual fact
//! pipeline; transit framing belongs to the transit handler lane and is not
//! produced here.

pub mod driver;
pub mod intent;

pub use driver::ConnectionResponseHandler;
pub use intent::{
    connection_response_intent, decode_connection_response_intent, ConnectionResponseIntent,
    CONNECTION_RESPONSE,
};
