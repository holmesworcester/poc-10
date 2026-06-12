//! Local recipient key authenticator.
//!
//! POLICY. Authenticating a `local_recipient_key` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical local recipient key fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local-only facts, never signed envelopes, so there is no
//! fact-boundary signature. Admission scope (`Local`), the shared-recipient
//! match, supersession, and materialization are all interpretation the
//! projector owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::LocalRecipientKeyFact;

pub(crate) fn authenticate(
    fact: &Fact,
    local: LocalRecipientKeyFact,
    _context: &ProjectionContext,
) -> Result<LocalRecipientKeyFact, String> {
    prove_decoded_local_recipient_key(fact, local)
}

fn prove_decoded_local_recipient_key(
    fact: &Fact,
    local: LocalRecipientKeyFact,
) -> Result<LocalRecipientKeyFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(local)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::{self, X25519_PRIVATE_KEY_BYTES};
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::auth::local_recipient_key::encode;
    use crate::protocol::auth::local_recipient_key::fact::LocalRecipientKeyFact;

    fn canonical_fact() -> Fact {
        let recipient_secret = [7; X25519_PRIVATE_KEY_BYTES];
        let recipient_key = crypto::x25519_public_key(&recipient_secret);
        let local = LocalRecipientKeyFact {
            workspace_id: [1; 32],
            recipient_key_id: [2; 32],
            recipient_key,
            recipient_secret,
        };
        let bytes = encode::encode_local_recipient_key(&local).expect("encode local recipient key");
        Fact::new(FactScope::Local, 123, bytes)
    }

    fn authenticate(fact: &Fact) -> Result<LocalRecipientKeyFact, String> {
        let decoded = super::super::decode::decode_local_recipient_key(fact.body())?;
        super::authenticate(fact, decoded, &ProjectionContext::default())
    }

    fn is_invalid(fact: &Fact) -> bool {
        authenticate(fact).is_err()
    }

    #[test]
    fn authenticates_canonical_fact() {
        assert!(authenticate(&canonical_fact()).is_ok());
    }

    #[test]
    fn rejects_wrong_tag() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes[0] ^= 0xff;
        assert!(is_invalid(&Fact::new(
            canonical.scope,
            canonical.timestamp,
            bytes
        )));
    }

    #[test]
    fn rejects_truncated_bytes() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes.pop();
        assert!(is_invalid(&Fact::new(
            canonical.scope,
            canonical.timestamp,
            bytes
        )));
    }

    #[test]
    fn rejects_id_not_matching_bytes() {
        let canonical = canonical_fact();
        let forged = Fact {
            id: [0; 32],
            scope: canonical.scope.clone(),
            timestamp: canonical.timestamp,
            bytes: canonical.bytes.clone(),
        };
        assert!(is_invalid(&forged));
    }
}
