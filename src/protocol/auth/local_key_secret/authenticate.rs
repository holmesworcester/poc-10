//! Local key secret authenticator.
//!
//! POLICY. Authenticating a `local_key_secret` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical local key secret fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local-only secrets, never signed envelopes, so there is no
//! fact-boundary signature. Admission scope (`Local`), the removal-frontier
//! match, retirement, and materialization are all interpretation the projector
//! owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::LocalKeySecretFact;

pub(crate) struct LocalKeySecretAuthenticator;

impl DecodedAuthenticator<super::Codec> for LocalKeySecretAuthenticator {
    type Authenticated = LocalKeySecretFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        secret: LocalKeySecretFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_local_key_secret(fact, secret))
    }
}

fn prove_decoded_local_key_secret(
    fact: &Fact,
    secret: LocalKeySecretFact,
) -> Result<LocalKeySecretFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::auth::local_key_secret::encode;
    use crate::protocol::auth::local_key_secret::fact::LocalKeySecretFact;

    use super::LocalKeySecretAuthenticator;

    fn canonical_fact() -> Fact {
        let secret = LocalKeySecretFact {
            workspace_id: [1; 32],
            frontier_id: [2; 32],
            owner_endpoint_id: [3; 32],
            created_at_ms: 123,
            key_secret: [4; 32],
        };
        let bytes = encode::encode_local_key_secret(&secret).expect("encode local key secret");
        Fact::new(FactScope::Local, 123, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, LocalKeySecretFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => LocalKeySecretAuthenticator::authenticate_decoded(
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
