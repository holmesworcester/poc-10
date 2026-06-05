//! Local recipient-key fact construction helpers.

use crate::core::crypto::{X25519PrivateKey, X25519PublicKey};
use crate::core::facts::{Fact, FactId, FactScope};

use super::encode;
use super::fact::LocalRecipientKeyFact;

pub fn recipient_key_fact(
    workspace_id: FactId,
    recipient_key_id: FactId,
    recipient_key: X25519PublicKey,
    recipient_secret: X25519PrivateKey,
    created_at_ms: u64,
) -> Result<(LocalRecipientKeyFact, Fact), String> {
    let key = LocalRecipientKeyFact {
        workspace_id,
        recipient_key_id,
        recipient_key,
        recipient_secret,
    };
    let fact = Fact::new(
        FactScope::Local,
        created_at_ms,
        encode::encode_local_recipient_key(&key)?,
    );
    Ok((key, fact))
}
