//! Byte decoding for invite-accepted facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id and
//! hash checks live in `authenticate.rs`.

use crate::core::wire;
use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
use crate::protocol::connection::request::{
    decode::decode_optional_addr, encode::ADDR_BLOCK_BYTES,
};

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
    let mut cursor = 1;
    let workspace_id = take_id(bytes, &mut cursor);
    let invite_fact_id = take_id(bytes, &mut cursor);
    let bootstrap_hash = take_id(bytes, &mut cursor);
    let bootstrap_secret = take_id(bytes, &mut cursor);
    let accepted_endpoint_id = take_id(bytes, &mut cursor);
    let bootstrap_endpoint_id = take_id(bytes, &mut cursor);
    let mut addr = [0u8; ADDR_BLOCK_BYTES];
    addr.copy_from_slice(&bytes[cursor..cursor + ADDR_BLOCK_BYTES]);
    cursor += ADDR_BLOCK_BYTES;
    let user_authority = take_id(bytes, &mut cursor);
    let endpoint_role = EndpointRole::from_u8(bytes[cursor])?;
    cursor += 1;
    let identity_scope = match bytes[cursor] {
        0 => false,
        1 => true,
        other => {
            return Err(format!(
                "invite_accepted identity_scope has invalid value {other}"
            ))
        }
    };
    let bootstrap_addr = decode_optional_addr(&addr)?
        .ok_or_else(|| "invite_accepted bootstrap_addr cannot be empty".to_string())?;
    Ok(InviteAcceptedFact {
        workspace_id,
        invite_fact_id,
        bootstrap_hash,
        bootstrap_secret,
        accepted_endpoint_id,
        bootstrap_endpoint_id,
        bootstrap_addr,
        user_authority_fact_id: (user_authority != [0; 32]).then_some(user_authority),
        endpoint_role,
        identity_scope,
    })
}

fn take_id(bytes: &[u8], cursor: &mut usize) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(&bytes[*cursor..*cursor + 32]);
    *cursor += 32;
    out
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::auth::invite_accepted::encode::{encode_fact, FACT_BYTES};

    fn fact() -> InviteAcceptedFact {
        InviteAcceptedFact {
            workspace_id: [1; 32],
            invite_fact_id: [2; 32],
            bootstrap_hash: crate::protocol::auth::invite::fact::bootstrap_secret_hash(&[7; 32]),
            bootstrap_secret: [7; 32],
            accepted_endpoint_id: [5; 32],
            bootstrap_endpoint_id: [6; 32],
            bootstrap_addr: "127.0.0.1:41000".parse().unwrap(),
            user_authority_fact_id: Some([8; 32]),
            endpoint_role: EndpointRole::Device,
            identity_scope: true,
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
