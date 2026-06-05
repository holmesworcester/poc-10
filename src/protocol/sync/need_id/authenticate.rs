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
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::SyncNeedIdFact;

pub(crate) struct SyncNeedIdAuthenticator;

impl DecodedAuthenticator<super::Codec> for SyncNeedIdAuthenticator {
    type Authenticated = SyncNeedIdFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        need: SyncNeedIdFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_need_id(fact, need))
    }
}

fn prove_decoded_need_id(fact: &Fact, need: SyncNeedIdFact) -> Result<SyncNeedIdFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(need)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::sync::need_id::author::fact as need_id_fact;
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
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => SyncNeedIdAuthenticator::authenticate_decoded(
                fact,
                decoded,
                &ProjectionContext::default(),
            ),
            Err(error) => Authentication::Invalid(error),
        }
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
