//! Connection ephemeral-secret authenticator.
//!
//! POLICY. Authenticating a `connection_ephemeral_secret` fact proves, over its
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical ephemeral-secret fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   FIELDS. The stored public key re-derives from the private key.
//!
//! It proves nothing else. Admission scope (`Local`) and the close gate are
//! interpretation the projector owns.

use crate::core::crypto;
use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::ConnectionEphemeralSecretFact;

pub(crate) struct ConnectionEphemeralSecretAuthenticator;

impl DecodedAuthenticator<super::Codec> for ConnectionEphemeralSecretAuthenticator {
    type Authenticated = ConnectionEphemeralSecretFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        secret: ConnectionEphemeralSecretFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_ephemeral_secret(fact, secret))
    }
}

fn prove_decoded_ephemeral_secret(
    fact: &Fact,
    secret: ConnectionEphemeralSecretFact,
) -> Result<ConnectionEphemeralSecretFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    // Intrinsic fields.
    if crypto::x25519_public_key(&secret.ephemeral_private_key) != secret.ephemeral_public_key {
        return Err("connection ephemeral public key does not match private key".to_string());
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::connection::ephemeral_secret::encode;
    use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;

    use super::ConnectionEphemeralSecretAuthenticator;

    const PRIVATE_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        let secret = ConnectionEphemeralSecretFact {
            owner_endpoint: [1; 32],
            ephemeral_private_key: PRIVATE_KEY,
            ephemeral_public_key: crypto::x25519_public_key(&PRIVATE_KEY),
            created_at_ms: 4,
        };
        Fact::new(
            FactScope::Local,
            100,
            encode::encode_fact(&secret).expect("encode ephemeral secret"),
        )
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ConnectionEphemeralSecretFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => ConnectionEphemeralSecretAuthenticator::authenticate_decoded(
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
