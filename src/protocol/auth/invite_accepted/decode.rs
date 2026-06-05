//! Byte decoding for invite-accepted facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id
//! checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{FACT_BYTES, TYPE_INVITE_ACCEPTED};
use super::fact::InviteAcceptedFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = InviteAcceptedFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<InviteAcceptedFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_INVITE_ACCEPTED {
        return Err("expected invite_accepted fact".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&bytes[1..33]);
    let mut invite_fact_id = [0; 32];
    invite_fact_id.copy_from_slice(&bytes[33..65]);
    let mut invite_secret_fact_id = [0; 32];
    invite_secret_fact_id.copy_from_slice(&bytes[65..97]);
    let mut bootstrap_hash = [0; 32];
    bootstrap_hash.copy_from_slice(&bytes[97..129]);
    let mut accepted_endpoint_id = [0; 32];
    accepted_endpoint_id.copy_from_slice(&bytes[129..161]);
    Ok(InviteAcceptedFact {
        workspace_id,
        invite_fact_id,
        invite_secret_fact_id,
        bootstrap_hash,
        accepted_endpoint_id,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::invite_accepted::encode::{encode_fact, FACT_BYTES};

    fn fact() -> InviteAcceptedFact {
        InviteAcceptedFact {
            workspace_id: [1; 32],
            invite_fact_id: [2; 32],
            invite_secret_fact_id: [3; 32],
            bootstrap_hash: [4; 32],
            accepted_endpoint_id: [5; 32],
        }
    }

    #[test]
    fn invite_accepted_fact_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = 0;
        assert!(decode_fact(&encoded).is_err());
    }
}
