//! Sync need-id authenticator.
//!
//! POLICY. Authenticating a `sync_need_id` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical need-id request.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! It proves nothing else. A need-id fact carries no fact-boundary signature;
//! whether this store can answer the request is idempotent handler work the
//! projector and its intents own.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::SyncNeedIdFact;

pub(crate) struct SyncNeedIdAuthenticator;

impl Authenticator for SyncNeedIdAuthenticator {
    type Authenticated = SyncNeedIdFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_need_id(fact))
    }
}

fn authenticate_need_id(fact: &Fact) -> Result<SyncNeedIdFact, String> {
    // 1. Layout.
    let need = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(need)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::sync::need_id::create::fact as need_id_fact;
    use crate::protocol::sync::need_id::fact::SyncNeedIdFact;

    use super::SyncNeedIdAuthenticator;

    fn canonical_fact() -> Fact {
        need_id_fact(
            SyncNeedIdFact {
                connection_id: [4; 32],
                fact_id: [8; 32],
            },
            777,
        )
        .expect("need-id fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, SyncNeedIdFact> {
        SyncNeedIdAuthenticator::authenticate(fact, &ProjectionContext::default())
    }

    fn is_invalid(fact: &Fact) -> bool {
        matches!(authenticate(fact), Authentication::Invalid(_))
    }

    #[test]
    fn authenticates_canonical_fact() {
        assert!(matches!(
            authenticate(&canonical_fact()),
            Authentication::Authenticated(_)
        ));
    }

    #[test]
    fn rejects_wrong_tag() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes[0] ^= 0xff;
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
    }

    #[test]
    fn rejects_truncated_bytes() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes.pop();
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
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
