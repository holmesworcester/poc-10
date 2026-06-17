//! Deterministic constructors for admin grant facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need store-queried local capabilities,
//! or multi-fact orchestration belong in `api.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth::admin::encode;
use crate::protocol::auth::admin::fact::AdminFact;

pub fn authored_admin_fact(
    created_at_ms: u64,
    signer_id: FactId,
    signer_private_key: Ed25519PrivateKey,
    mut grant: AdminFact,
) -> Result<Fact, String> {
    grant.signer_id = signer_id;
    grant.signer_public_key = crypto::ed25519_public_key(&signer_private_key);
    Ok(Fact::new(
        FactScope::Global,
        created_at_ms,
        encode::encode_fact(&grant)?,
    ))
}
