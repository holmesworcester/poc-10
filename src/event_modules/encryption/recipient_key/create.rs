//! Validation helper for retired-recipient-material purge intents.

use super::intent::PurgeRetiredRecipientMaterialIntent;
use super::layout;
use crate::core::facts::{Fact, FactScope};

pub fn validate_retired_recipient_material(
    intent: &PurgeRetiredRecipientMaterialIntent,
    local_recipient_key_fact: &Fact,
) -> Result<(), String> {
    if local_recipient_key_fact.id != intent.local_recipient_key_id {
        return Err("local recipient key fact id does not match purge intent".to_string());
    }
    if local_recipient_key_fact.scope != FactScope::Local {
        return Err("retired recipient material is not local".to_string());
    }
    let local = layout::decode_local_recipient_key(&local_recipient_key_fact.bytes)?;
    if local.workspace_id != intent.workspace_id {
        return Err("retired recipient material workspace mismatch".to_string());
    }
    if local.recipient_key_id != intent.recipient_key_id {
        return Err("retired recipient material recipient mismatch".to_string());
    }
    Ok(())
}
