//! Byte decoding for device-invite facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id and
//! signature checks live in `authenticate.rs`.

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::encode::{FACT_BYTES, TYPE_DEVICE_INVITE};
use super::fact::DeviceInviteFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = DeviceInviteFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<DeviceInviteFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_DEVICE_INVITE {
        return Err("expected device_invite fact".to_string());
    }
    let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&bytes[9..41]);
    let mut user_authority_fact_id = [0; 32];
    user_authority_fact_id.copy_from_slice(&bytes[41..73]);
    let mut user_invite_raw = [0; 32];
    user_invite_raw.copy_from_slice(&bytes[73..105]);
    let user_invite_fact_id = if user_invite_raw == [0; 32] {
        None
    } else {
        Some(user_invite_raw)
    };
    let mut public_key = [0; 32];
    public_key.copy_from_slice(&bytes[105..137]);
    let mut signer_id = [0; 32];
    signer_id.copy_from_slice(&bytes[137..169]);
    let mut signer_public_key = [0; 32];
    signer_public_key.copy_from_slice(&bytes[169..201]);
    let mut signature = [0; ED25519_SIGNATURE_BYTES];
    signature.copy_from_slice(&bytes[201..265]);
    Ok(DeviceInviteFact {
        created_at_ms,
        workspace_id,
        user_authority_fact_id,
        user_invite_fact_id,
        public_key,
        signer_id,
        signer_public_key,
        signature,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::ED25519_SIGNATURE_BYTES;
    use crate::protocol::auth::device_invite::encode::{encode_fact, FACT_BYTES};

    fn fact() -> DeviceInviteFact {
        DeviceInviteFact {
            created_at_ms: 11,
            workspace_id: [1; 32],
            user_authority_fact_id: [2; 32],
            user_invite_fact_id: Some([4; 32]),
            public_key: [3; 32],
            signer_id: [2; 32],
            signer_public_key: [5; 32],
            signature: [6; ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn device_invite_fact_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn zero_user_invite_roundtrips_as_none() {
        let fact = DeviceInviteFact {
            user_invite_fact_id: None,
            ..fact()
        };
        let encoded = encode_fact(&fact).expect("encode");
        assert_eq!(decode_fact(&encoded).expect("decode"), fact);
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = 0;
        assert!(decode_fact(&encoded).is_err());
    }
}
