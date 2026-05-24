//! Connection response family.
//!
//! A response completes a handshake and is the local connection fact: its fact
//! id is the connection id, and its body contains the connection secret used to
//! open established frames. Projection validates request and secret context,
//! writes connection rows, publishes local connection context, and seeds sync.
//!
//! This family owns response payload bytes, responder key-schedule
//! construction, row materialization, and response admission policy. Frame
//! sending and sync fact selection use the materialized connection but do not
//! define it.

pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub fn seed_sync_timeline() -> crate::core::projectors::Timeline {
    crate::core::projectors::Timeline::new("connection_seed_sync")
        .expect("valid connection seed-sync timeline")
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionResponseFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionResponseFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
