//! Byte decoding for removal frontier facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id and
//! id checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{REMOVAL_FRONTIER_BYTES, TYPE_REMOVAL_FRONTIER};
use super::fact::RemovalFrontierFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = RemovalFrontierFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_removal_frontier(fact.body())
    }
}

pub fn decode_removal_frontier(bytes: &[u8]) -> Result<RemovalFrontierFact, String> {
    wire::expect_len(bytes, REMOVAL_FRONTIER_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_REMOVAL_FRONTIER {
        return Err("expected removal frontier".to_string());
    }
    Ok(RemovalFrontierFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        owner_endpoint_id: bytes[33..65].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[65..73]).map_err(wire_err)?,
        signer_public_key: bytes[73..105].try_into().unwrap(),
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::removal_frontier::encode::{
        encode_removal_frontier, REMOVAL_FRONTIER_BYTES,
    };

    fn sample_fact() -> RemovalFrontierFact {
        RemovalFrontierFact {
            workspace_id: [1; 32],
            owner_endpoint_id: [2; 32],
            created_at_ms: 123,
            signer_public_key: [3; 32],
        }
    }

    #[test]
    fn removal_frontier_roundtrips_fixed_width() {
        let fact = sample_fact();

        let encoded = encode_removal_frontier(&fact).expect("encode removal frontier");

        assert_eq!(encoded.len(), REMOVAL_FRONTIER_BYTES);
        assert_eq!(
            decode_removal_frontier(&encoded).expect("decode removal frontier"),
            fact
        );
    }
}
