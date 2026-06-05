//! Canonical byte encoding for local connection ephemeral-secret facts.
//!
//! This file owns byte construction only: the fact tag and the fixed field
//! order and widths. It does not decide whether the keypair is valid or whether
//! the local fact should be admitted.
//!
//! The layout is fixed width: `tag(1) || owner_endpoint(32) ||
//! ephemeral_private_key(32) || ephemeral_public_key(32) ||
//! created_at_ms(8)`.
//!
//! Change this file only for wire compatibility of the secret fact. Keypair
//! validation belongs in `project.rs`, and durable row shape belongs in the
//! family manifest's row schema.

use crate::core::crypto::{X25519_PRIVATE_KEY_BYTES, X25519_PUBLIC_KEY_BYTES};
use crate::core::wire;

use super::fact::ConnectionEphemeralSecretFact;

pub const TYPE_CONNECTION_EPHEMERAL_SECRET: u8 = 43;

pub const FACT_BYTES: usize = 1 + 32 + X25519_PRIVATE_KEY_BYTES + X25519_PUBLIC_KEY_BYTES + 8;

pub fn encode_fact(fact: &ConnectionEphemeralSecretFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_EPHEMERAL_SECRET, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.owner_endpoint);
    out[33..65].copy_from_slice(&fact.ephemeral_private_key);
    out[65..97].copy_from_slice(&fact.ephemeral_public_key);
    wire::put_u64be(fact.created_at_ms, &mut out[97..105]).map_err(wire_err)?;
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
