//! Fixed-width invite-accepted fact and projection-row layout.

use crate::core::wire;

use super::fact::InviteAcceptedFact;

pub const TYPE_INVITE_ACCEPTED: u8 = 146;
/// Layout: `type(1) || workspace_id(32) || invite_fact_id(32) ||
/// invite_secret_fact_id(32) || bootstrap_hash(32) || accepted_endpoint_id(32)`.
pub const FACT_BYTES: usize = 1 + 32 + 32 + 32 + 32 + 32;
/// Row value layout: `invite_accepted_fact_id(32) || invite_secret_fact_id(32) ||
/// bootstrap_hash(32)`.
pub const ROW_VALUE_BYTES: usize = 32 + 32 + 32;

pub fn encode_fact(fact: &InviteAcceptedFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_INVITE_ACCEPTED, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.invite_fact_id);
    out[65..97].copy_from_slice(&fact.invite_secret_fact_id);
    out[97..129].copy_from_slice(&fact.bootstrap_hash);
    out[129..161].copy_from_slice(&fact.accepted_endpoint_id);
    Ok(out)
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

pub(crate) fn encode_row_value(
    invite_accepted_fact_id: &[u8; 32],
    fact: &InviteAcceptedFact,
) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ROW_VALUE_BYTES];
    out[0..32].copy_from_slice(invite_accepted_fact_id);
    out[32..64].copy_from_slice(&fact.invite_secret_fact_id);
    out[64..96].copy_from_slice(&fact.bootstrap_hash);
    Ok(out)
}

pub(crate) fn decode_row_value(value: &[u8]) -> Result<DecodedRowValue, String> {
    wire::expect_len(value, ROW_VALUE_BYTES).map_err(wire_err)?;
    let mut invite_accepted_fact_id = [0; 32];
    invite_accepted_fact_id.copy_from_slice(&value[0..32]);
    let mut invite_secret_fact_id = [0; 32];
    invite_secret_fact_id.copy_from_slice(&value[32..64]);
    let mut bootstrap_hash = [0; 32];
    bootstrap_hash.copy_from_slice(&value[64..96]);
    Ok(DecodedRowValue {
        invite_accepted_fact_id,
        invite_secret_fact_id,
        bootstrap_hash,
    })
}

pub(crate) struct DecodedRowValue {
    pub invite_accepted_fact_id: [u8; 32],
    pub invite_secret_fact_id: [u8; 32],
    pub bootstrap_hash: [u8; 32],
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn row_value_roundtrip() {
        let value = encode_row_value(&[9; 32], &fact()).expect("row value");
        let decoded = decode_row_value(&value).expect("decode row");
        assert_eq!(decoded.invite_accepted_fact_id, [9; 32]);
        assert_eq!(decoded.invite_secret_fact_id, [3; 32]);
        assert_eq!(decoded.bootstrap_hash, [4; 32]);
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = 0;
        assert!(decode_fact(&encoded).is_err());
    }
}
