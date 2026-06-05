//! Canonical byte encoding for endpoint-shared facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths, the projection row value bytes. It does not sign, authenticate, inspect context, or materialize rows.
//!
//! Inner payload layout:
//!
//! ```text
//! type(1) || created_at_ms(8) || workspace_id(32)
//!   || user_authority_fact_id(32) || endpoint_id(32)
//!   || signing_public_key(32) || endpoint_role(1)
//!   || device_name_utf8_zero_padded(64)
//! ```

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::fact::{EndpointDeviceName, EndpointSharedFact, ENDPOINT_DEVICE_NAME_BYTES};

pub const TYPE_ENDPOINT_SHARED: u8 = 135;
pub const FACT_BYTES: usize =
    1 + 8 + 32 + 32 + 32 + 32 + 1 + ENDPOINT_DEVICE_NAME_BYTES + 32 + 32 + ED25519_SIGNATURE_BYTES;
pub fn encode_fact(fact: &EndpointSharedFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_ENDPOINT_SHARED, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.workspace_id);
    out[41..73].copy_from_slice(&fact.user_authority_fact_id);
    out[73..105].copy_from_slice(&fact.endpoint_id);
    out[105..137].copy_from_slice(&fact.signing_public_key);
    wire::put_u8(fact.endpoint_role.as_u8(), &mut out[137..138]).map_err(wire_err)?;
    write_device_name(
        &fact.device_name,
        &mut out[138..138 + ENDPOINT_DEVICE_NAME_BYTES],
    )?;
    let signer_start = 138 + ENDPOINT_DEVICE_NAME_BYTES;
    out[signer_start..signer_start + 32].copy_from_slice(&fact.signer_id);
    out[signer_start + 32..signer_start + 64].copy_from_slice(&fact.signer_public_key);
    out[signer_start + 64..signer_start + 64 + ED25519_SIGNATURE_BYTES]
        .copy_from_slice(&fact.signature);
    Ok(out)
}

fn write_device_name(name: &EndpointDeviceName, out: &mut [u8]) -> Result<(), String> {
    wire::expect_len(out, ENDPOINT_DEVICE_NAME_BYTES).map_err(wire_err)?;
    out.copy_from_slice(name.padded_bytes());
    Ok(())
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
