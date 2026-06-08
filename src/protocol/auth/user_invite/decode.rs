//! Byte decoding for user-invite facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id and
//! id checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{FACT_BYTES, TYPE_USER_INVITE};
use super::fact::UserInviteFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = UserInviteFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<UserInviteFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_USER_INVITE {
        return Err("expected user_invite fact".to_string());
    }
    let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
    let mut public_key = [0; 32];
    public_key.copy_from_slice(&bytes[9..41]);
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&bytes[41..73]);
    let mut authority_fact_id = [0; 32];
    authority_fact_id.copy_from_slice(&bytes[73..105]);
    let mut signer_id = [0; 32];
    signer_id.copy_from_slice(&bytes[105..137]);
    let mut signer_public_key = [0; 32];
    signer_public_key.copy_from_slice(&bytes[137..169]);
    Ok(UserInviteFact {
        created_at_ms,
        public_key,
        workspace_id,
        authority_fact_id,
        signer_id,
        signer_public_key,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::user_invite::encode::{encode_fact, FACT_BYTES};

    fn fact() -> UserInviteFact {
        UserInviteFact {
            created_at_ms: 5,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_fact_id: [3; 32],
            signer_id: [3; 32],
            signer_public_key: [4; 32],
        }
    }

    #[test]
    fn user_invite_fact_roundtrips_fixed_width() {
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
