//! Local secret-retirement fact construction helpers.

use crate::core::facts::{Fact, FactId, FactScope};

use super::encode;
use super::fact::{LocalSecretRetirementFact, RETIRE_REASON_CHOP};

pub fn chop_retirement_fact(
    workspace_id: FactId,
    target_secret_id: FactId,
    floor_minute: u64,
    created_at_ms: u64,
) -> Result<(LocalSecretRetirementFact, Fact), String> {
    let retirement = LocalSecretRetirementFact {
        workspace_id,
        target_secret_id,
        reason_kind: RETIRE_REASON_CHOP,
        floor_minute,
        created_at_ms,
    };
    let fact = Fact::new(
        FactScope::Local,
        created_at_ms,
        encode::encode_fact(&retirement)?,
    );
    Ok((retirement, fact))
}
