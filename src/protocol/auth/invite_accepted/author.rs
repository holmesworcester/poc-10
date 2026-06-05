//! Invite-accepted fact construction helpers.

use crate::core::facts::{Fact, FactId, FactScope};

use super::encode;
use super::fact::InviteAcceptedFact;

pub fn accepted_fact(
    workspace_id: FactId,
    invite_fact_id: FactId,
    invite_secret_fact_id: FactId,
    bootstrap_hash: FactId,
    accepted_endpoint_id: FactId,
    created_at_ms: u64,
) -> Result<(InviteAcceptedFact, Fact), String> {
    let accepted = InviteAcceptedFact {
        workspace_id,
        invite_fact_id,
        invite_secret_fact_id,
        bootstrap_hash,
        accepted_endpoint_id,
    };
    let fact = Fact::new(
        FactScope::Local,
        created_at_ms,
        encode::encode_fact(&accepted)?,
    );
    Ok((accepted, fact))
}
