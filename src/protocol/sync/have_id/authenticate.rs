//! Sync have-id authenticator.
//!
//! POLICY. Authenticating a `sync_have_id` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical have-id advertisement.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! It proves nothing else. A have-id fact carries no fact-boundary signature;
//! whether the advertised id is already present is idempotent handler work the
//! projector and its intents own.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::SyncHaveIdFact;

pub(crate) struct SyncHaveIdAuthenticator;

impl Authenticator for SyncHaveIdAuthenticator {
    type Authenticated = SyncHaveIdFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_have_id(fact))
    }
}

fn authenticate_have_id(fact: &Fact) -> Result<SyncHaveIdFact, String> {
    // 1. Layout.
    let have = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(have)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::sync::have_id::create::advertisement_fact;
    use crate::protocol::sync::have_id::fact::SyncHaveIdFact;

    use super::SyncHaveIdAuthenticator;

    fn canonical_fact() -> Fact {
        let advertised = Fact::new(FactScope::Global, 777, vec![42]);
        advertisement_fact([7; 32], &advertised).expect("have-id advertisement fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, SyncHaveIdFact> {
        SyncHaveIdAuthenticator::authenticate(fact, &ProjectionContext::default())
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
