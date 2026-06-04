//! Removal-frontier authenticator.
//!
//! POLICY. Authenticating a `removal_frontier` fact proves, over its signed
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical removal-frontier fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!
//! Scope and owner-endpoint authority (an `endpoint_shared` signer or a local
//! signer secret) are interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::RemovalFrontierFact;

pub(crate) struct RemovalFrontierAuthenticator;

impl Authenticator for RemovalFrontierAuthenticator {
    type Authenticated = RemovalFrontierFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_removal_frontier(fact))
    }
}

fn authenticate_removal_frontier(fact: &Fact) -> Result<RemovalFrontierFact, String> {
    // 1. Layout.
    let frontier = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&frontier)?;
    Ok(frontier)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::auth::removal_frontier::create::signed_removal_frontier_fact;
    use crate::protocol::auth::removal_frontier::fact::RemovalFrontierFact;

    use super::RemovalFrontierAuthenticator;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        signed_removal_frontier_fact([1; 32], [2; 32], 100, SIGNER_KEY)
            .expect("signed removal_frontier fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, RemovalFrontierFact> {
        RemovalFrontierAuthenticator::authenticate(fact, &ProjectionContext::default())
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
    fn rejects_tampered_signature() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
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
