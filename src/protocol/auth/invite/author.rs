//! Invite-secret fact construction helpers.

use crate::core::crypto::Ed25519PrivateKey;
use crate::core::facts::{Fact, FactId, FactScope};

use super::encode;
use super::fact::InviteSecretFact;

pub fn secret_fact(secret: InviteSecretFact, created_at_ms: u64) -> Result<Fact, String> {
    Ok(Fact::new(
        FactScope::Local,
        created_at_ms,
        encode::encode_fact(&secret)?,
    ))
}

pub fn unscoped_secret_fact(
    bootstrap_secret: Ed25519PrivateKey,
    created_at_ms: u64,
) -> Result<(InviteSecretFact, Fact), String> {
    let secret = InviteSecretFact::new(bootstrap_secret);
    let fact = secret_fact(secret, created_at_ms)?;
    Ok((secret, fact))
}

pub fn scoped_secret_fact(
    bootstrap_secret: Ed25519PrivateKey,
    workspace_id: FactId,
    invite_fact_id: FactId,
    created_at_ms: u64,
) -> Result<(InviteSecretFact, Fact), String> {
    let secret = InviteSecretFact::scoped(bootstrap_secret, workspace_id, invite_fact_id);
    let fact = secret_fact(secret, created_at_ms)?;
    Ok((secret, fact))
}
