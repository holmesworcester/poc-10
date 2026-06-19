//! Canonical byte encoding for local key-wrap creation facts.
//!
//! This file owns the fixed local work-fact layout. Projection owns checking
//! that the named recipient, source, and signer facts actually match.

use crate::core::wire;
use crate::protocol::auth::key_wrap::fact::WrapSourceKind;

use super::fact::KeyWrapCreationFact;

pub const TYPE_KEY_WRAP_CREATION: u8 = 158;
pub const KEY_WRAP_CREATION_BYTES: usize = 1 + 32 + 32 + 32 + 32 + 32 + 32 + 8 + 1 + 50;

pub fn encode_fact(fact: &KeyWrapCreationFact) -> Result<Vec<u8>, String> {
    validate_fact(fact)?;
    let mut out = vec![0; KEY_WRAP_CREATION_BYTES];
    wire::put_u8(TYPE_KEY_WRAP_CREATION, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.frontier_id);
    out[65..97].copy_from_slice(&fact.recipient_key_id);
    out[97..129].copy_from_slice(&fact.source_fact_id);
    out[129..161].copy_from_slice(&fact.signer_secret_fact_id);
    out[161..193].copy_from_slice(&fact.owner_endpoint_id);
    wire::put_u64be(fact.frontier_created_at_ms, &mut out[193..201]).map_err(wire_err)?;
    match fact.source {
        WrapSourceKind::FrontierRoot => {
            out[201] = 1;
        }
        WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            fact_id_prefix,
        } => {
            out[201] = 2;
            wire::put_u64be(range_start, &mut out[202..210]).map_err(wire_err)?;
            wire::put_u64be(range_width, &mut out[210..218]).map_err(wire_err)?;
            wire::put_u16be(bit_depth, &mut out[218..220]).map_err(wire_err)?;
            out[220..252].copy_from_slice(&fact_id_prefix);
        }
    }
    Ok(out)
}

pub(crate) fn validate_fact(fact: &KeyWrapCreationFact) -> Result<(), String> {
    for (name, id) in [
        ("key wrap creation workspace_id", &fact.workspace_id),
        ("key wrap creation frontier_id", &fact.frontier_id),
        ("key wrap creation recipient_key_id", &fact.recipient_key_id),
        ("key wrap creation source_fact_id", &fact.source_fact_id),
        (
            "key wrap creation signer_secret_fact_id",
            &fact.signer_secret_fact_id,
        ),
        (
            "key wrap creation owner_endpoint_id",
            &fact.owner_endpoint_id,
        ),
    ] {
        if id.iter().all(|byte| *byte == 0) {
            return Err(format!("{name} cannot be empty"));
        }
    }
    match fact.source {
        WrapSourceKind::FrontierRoot => Ok(()),
        WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            fact_id_prefix,
        } => {
            crate::protocol::auth::local_history_node_secret::encode::validate_history_node_coordinate(
                range_start,
                range_width,
                bit_depth,
                fact_id_prefix,
            )
        }
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
