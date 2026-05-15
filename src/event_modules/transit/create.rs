//! Transit send construction helpers.
//!
//! This module owns fact-level sendability checks for outbound transit. The
//! handler may load the exact input facts from core, but it delegates protocol
//! knowledge such as private/local fact tags back here.

use crate::core::facts::{Fact, FactScope};
use crate::event_modules::{encryption, signed_fact};

/// Return the bytes that may be packaged into a transit frame.
///
/// Local facts and private/local fact tags are never transport payloads. A
/// signed envelope is decoded here as a defensive check that the envelope
/// itself is valid and does not hide a private local payload type.
pub fn require_sendable_fact(fact: &Fact) -> Result<&[u8], String> {
    if fact.scope == FactScope::Local {
        return Err(format!("transit send refused local fact {:?}", fact.id));
    }

    let tag = fact
        .bytes
        .first()
        .copied()
        .ok_or_else(|| format!("transit send refused empty fact {:?}", fact.id))?;
    if is_private_local_fact_tag(tag) {
        return Err(format!(
            "transit send refused private/local fact tag {tag} for {:?}",
            fact.id
        ));
    }

    if tag == signed_fact::layout::TYPE_SIGNED_FACT {
        let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes).map_err(|err| {
            format!(
                "transit send refused invalid signed fact {:?}: {err}",
                fact.id
            )
        })?;
        if is_private_local_fact_tag(envelope.inner_type) {
            return Err(format!(
                "transit send refused private/local signed payload tag {} for {:?}",
                envelope.inner_type, fact.id
            ));
        }
    }

    Ok(&fact.bytes)
}

pub fn is_private_local_fact_tag(tag: u8) -> bool {
    matches!(
        tag,
        signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET
            | encryption::layout::TYPE_LOCAL_KEY_SECRET
            | encryption::layout::TYPE_LOCAL_HISTORY_NODE_SECRET
            | encryption::layout::TYPE_LOCAL_RECIPIENT_KEY
    )
}
