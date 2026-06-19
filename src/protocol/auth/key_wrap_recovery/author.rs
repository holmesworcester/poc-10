//! Local key-wrap recovery fact construction helpers.

use crate::core::facts::{Fact, FactId, FactScope};

use super::{encode, fact::KeyWrapRecoveryFact};

pub fn key_wrap_recovery_fact(
    workspace_id: FactId,
    frontier_id: FactId,
    recipient_key_id: FactId,
    key_wrap_id: FactId,
    local_recipient_key_id: FactId,
    created_at_ms: u64,
) -> Result<Fact, String> {
    let recovery = KeyWrapRecoveryFact {
        workspace_id,
        frontier_id,
        recipient_key_id,
        key_wrap_id,
        local_recipient_key_id,
    };
    Ok(Fact::new(
        FactScope::Local,
        created_at_ms,
        encode::encode_fact(&recovery)?,
    ))
}
