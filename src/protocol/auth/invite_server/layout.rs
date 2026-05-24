//! Fixed-width layout for invite-server facts and rows.
//!
//! Invite-server facts advertise server-side invite material under workspace
//! authority. This module fixes their canonical byte shape and row value while
//! leaving authorization to projection. Change this file only when the durable
//! fact or projected row format changes.

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::wire;

use super::fact::InviteServerFact;

pub const TYPE_INVITE_SERVER: u8 = 136;
/// Layout: `type(1) || created_at_ms(8) || public_key(32) || workspace_id(32) ||
/// authority_fact_id(32)`.
pub const FACT_BYTES: usize = 1 + 8 + 32 + 32 + 32 + 32 + 32 + ED25519_SIGNATURE_BYTES;
const SIGNATURE_OFFSET: usize = FACT_BYTES - ED25519_SIGNATURE_BYTES;
/// Row value layout: `created_at_ms(8) || public_key(32) || authority_fact_id(32)`.
pub const ROW_VALUE_BYTES: usize = 8 + 32 + 32;

pub fn encode_fact(fact: &InviteServerFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_INVITE_SERVER, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.public_key);
    out[41..73].copy_from_slice(&fact.workspace_id);
    out[73..105].copy_from_slice(&fact.authority_fact_id);
    out[105..137].copy_from_slice(&fact.signer_id);
    out[137..169].copy_from_slice(&fact.signer_public_key);
    out[169..233].copy_from_slice(&fact.signature);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<InviteServerFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_INVITE_SERVER {
        return Err("expected invite_server fact".to_string());
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
    let mut signature = [0; ED25519_SIGNATURE_BYTES];
    signature.copy_from_slice(&bytes[169..233]);
    Ok(InviteServerFact {
        created_at_ms,
        public_key,
        workspace_id,
        authority_fact_id,
        signer_id,
        signer_public_key,
        signature,
    })
}

pub fn signing_bytes(fact: &InviteServerFact) -> Result<Vec<u8>, String> {
    wire::canonical_with_zeroed_field(&encode_fact(fact)?, SIGNATURE_OFFSET..FACT_BYTES)
        .map_err(wire_err)
}

pub fn verify_signature(fact: &InviteServerFact) -> Result<(), String> {
    crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &signing_bytes(fact)?,
        &fact.signature,
        "invite server",
    )
}

pub(crate) fn encode_row_value(fact: &InviteServerFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ROW_VALUE_BYTES];
    wire::put_u64be(fact.created_at_ms, &mut out[0..8]).map_err(wire_err)?;
    out[8..40].copy_from_slice(&fact.public_key);
    out[40..72].copy_from_slice(&fact.authority_fact_id);
    Ok(out)
}

pub(crate) fn decode_row_value(value: &[u8]) -> Result<DecodedRowValue, String> {
    wire::expect_len(value, ROW_VALUE_BYTES).map_err(wire_err)?;
    let created_at_ms = wire::take_u64be(&value[0..8]).map_err(wire_err)?;
    let mut public_key = [0; 32];
    public_key.copy_from_slice(&value[8..40]);
    let mut authority_fact_id = [0; 32];
    authority_fact_id.copy_from_slice(&value[40..72]);
    Ok(DecodedRowValue {
        created_at_ms,
        public_key,
        authority_fact_id,
    })
}

pub(crate) struct DecodedRowValue {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub authority_fact_id: [u8; 32],
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> InviteServerFact {
        InviteServerFact {
            created_at_ms: 9,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_fact_id: [3; 32],
            signer_id: [3; 32],
            signer_public_key: [4; 32],
            signature: [5; ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn invite_server_fact_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn row_value_roundtrip() {
        let value = encode_row_value(&fact()).expect("row value");
        let decoded = decode_row_value(&value).expect("decode row");
        assert_eq!(decoded.created_at_ms, 9);
        assert_eq!(decoded.public_key, [1; 32]);
        assert_eq!(decoded.authority_fact_id, [3; 32]);
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = 0;
        assert!(decode_fact(&encoded).is_err());
    }
}
