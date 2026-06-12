//! Byte decoding for local history-node secret facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order, then
//! re-runs the canonical encode to reject non-canonical coordinates. Id checks
//! live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{
    encode_local_history_node_secret, LOCAL_HISTORY_NODE_SECRET_BYTES,
    TYPE_LOCAL_HISTORY_NODE_SECRET,
};
use super::fact::LocalHistoryNodeSecretFact;

pub fn decode_local_history_node_secret(
    bytes: &[u8],
) -> Result<LocalHistoryNodeSecretFact, String> {
    wire::expect_len(bytes, LOCAL_HISTORY_NODE_SECRET_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_LOCAL_HISTORY_NODE_SECRET {
        return Err("expected local history node secret".to_string());
    }
    let fact = LocalHistoryNodeSecretFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        frontier_id: bytes[33..65].try_into().unwrap(),
        owner_endpoint_id: bytes[65..97].try_into().unwrap(),
        source_secret_id: bytes[97..129].try_into().unwrap(),
        range_start: wire::take_u64be(&bytes[129..137]).map_err(wire_err)?,
        range_width: wire::take_u64be(&bytes[137..145]).map_err(wire_err)?,
        bit_depth: wire::take_u16be(&bytes[145..147]).map_err(wire_err)?,
        fact_id_prefix: bytes[147..179].try_into().unwrap(),
        tombstone_node_id: bytes[179..211].try_into().unwrap(),
        node_secret: bytes[211..243].try_into().unwrap(),
    };
    encode_local_history_node_secret(&fact)?;
    Ok(fact)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::XCHACHA20_POLY1305_KEY_BYTES;
    use crate::protocol::auth::local_history_node_secret::encode::{
        encode_local_history_node_secret, LOCAL_HISTORY_NODE_SECRET_BYTES,
    };

    fn sample_fact() -> LocalHistoryNodeSecretFact {
        LocalHistoryNodeSecretFact {
            workspace_id: [1; 32],
            frontier_id: [2; 32],
            owner_endpoint_id: [3; 32],
            source_secret_id: [4; 32],
            range_start: 0,
            range_width: 1,
            bit_depth: 256,
            fact_id_prefix: [5; 32],
            tombstone_node_id: [6; 32],
            node_secret: [7; XCHACHA20_POLY1305_KEY_BYTES],
        }
    }

    #[test]
    fn local_history_node_secret_roundtrips_fixed_width() {
        let fact = sample_fact();

        let encoded =
            encode_local_history_node_secret(&fact).expect("encode local history node secret");

        assert_eq!(encoded.len(), LOCAL_HISTORY_NODE_SECRET_BYTES);
        assert_eq!(
            decode_local_history_node_secret(&encoded).expect("decode local history node secret"),
            fact
        );
    }
}
