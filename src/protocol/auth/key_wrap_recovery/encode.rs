//! Canonical byte encoding for local key-wrap recovery facts.

use crate::core::wire;

use super::fact::KeyWrapRecoveryFact;

pub const TYPE_KEY_WRAP_RECOVERY: u8 = 159;
pub const KEY_WRAP_RECOVERY_BYTES: usize = 1 + 32 * 5;

pub fn encode_fact(fact: &KeyWrapRecoveryFact) -> Result<Vec<u8>, String> {
    validate_fact(fact)?;
    let mut out = Vec::with_capacity(KEY_WRAP_RECOVERY_BYTES);
    out.push(TYPE_KEY_WRAP_RECOVERY);
    out.extend_from_slice(&fact.workspace_id);
    out.extend_from_slice(&fact.frontier_id);
    out.extend_from_slice(&fact.recipient_key_id);
    out.extend_from_slice(&fact.key_wrap_id);
    out.extend_from_slice(&fact.local_recipient_key_id);
    Ok(out)
}

pub(crate) fn validate_fact(fact: &KeyWrapRecoveryFact) -> Result<(), String> {
    for (name, id) in [
        ("key wrap recovery workspace_id", &fact.workspace_id),
        ("key wrap recovery frontier_id", &fact.frontier_id),
        ("key wrap recovery recipient_key_id", &fact.recipient_key_id),
        ("key wrap recovery key_wrap_id", &fact.key_wrap_id),
        (
            "key wrap recovery local_recipient_key_id",
            &fact.local_recipient_key_id,
        ),
    ] {
        if id.iter().all(|byte| *byte == 0) {
            return Err(format!("{name} cannot be empty"));
        }
    }
    Ok(())
}

pub(crate) fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
