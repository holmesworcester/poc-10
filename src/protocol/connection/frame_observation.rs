//! Received connection-frame observation fact family.
//!
//! A `connection_frame_observation` fact is durable local metadata saying this
//! daemon observed a canonical frame fact from a socket origin at a local time.
//! Frame facts contain only wire bytes; this family supplies the receive
//! context needed before those bytes may be opened.

pub mod authenticate;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionFrameObservationFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        layout::decode_fact(fact.body())
    }
}
