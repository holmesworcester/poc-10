//! Canonical byte encoding for signature evidence facts.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   target_fact_id (32)
//!   signer_public_key (32)
//!   signature (64)

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::fact::SignatureFact;

pub const TYPE_SIGNATURE: u8 = 140;
pub const SIGNATURE_FACT_BYTES: usize = 1 + 32 + 8 + 32 + 32 + ED25519_SIGNATURE_BYTES;
const SIGNATURE_FACT_DOMAIN: &[u8] = b"topo:poc10:signature-fact:v1";

pub fn encode_fact(fact: &SignatureFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(SIGNATURE_FACT_BYTES);
    out.u8(TYPE_SIGNATURE);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.target_fact_id);
    out.fixed(&fact.signer_public_key);
    out.fixed(&fact.signature);
    out.finish_exact(SIGNATURE_FACT_BYTES).map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

pub fn signature_message(
    workspace_id: crate::core::facts::FactId,
    target_fact_id: crate::core::facts::FactId,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNATURE_FACT_DOMAIN.len() + 1 + 32 + 32);
    out.extend_from_slice(SIGNATURE_FACT_DOMAIN);
    out.push(0);
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&target_fact_id);
    out
}
