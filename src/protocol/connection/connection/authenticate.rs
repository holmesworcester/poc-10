//! Connection authenticator.
//!
//! POLICY. Authenticating a `connection` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical sealed connection fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   FIELDS. The selector fields are non-empty, the two endpoints differ, and
//!   the connection does not answer itself.
//!
//! It proves nothing else. Admission scope (`Local`), the close gate, request
//! context, the handshake transcript, and ephemeral material are all
//! interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, AuthenticatedFact, Authentication, Authenticator, ProjectionContext,
};

pub(crate) struct ConnectionAuthenticator;

impl Authenticator for ConnectionAuthenticator {
    type Authenticated = ();

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        if let Err(error) = verify_fact_id(fact) {
            return Authentication::Invalid(error);
        }
        if let Err(error) = super::layout::validate_sealed_fact(fact.body()) {
            return Authentication::Invalid(error);
        }
        Authentication::Authenticated(AuthenticatedFact::new(fact, ()))
    }
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::connection::connection::fact::ConnectionFact;
    use crate::protocol::connection::connection::layout;

    use super::ConnectionAuthenticator;

    fn canonical_fact() -> Fact {
        let initiator_secret = [9; 32];
        let responder_ephemeral_private_key = [10; 32];
        let connection = ConnectionFact {
            from_endpoint: [1; 32],
            to_endpoint: crypto::x25519_public_key(&initiator_secret),
            request_id: [3; 32],
            responder_addr: Some("127.0.0.1:41002".parse().unwrap()),
            initiator_addr: Some("127.0.0.1:41001".parse().unwrap()),
            initiator_ephemeral_secret_fact_id: [4; 32],
            responder_ephemeral_secret_fact_id: [5; 32],
            responder_ephemeral_public_key: crypto::x25519_public_key(
                &responder_ephemeral_private_key,
            ),
            handshake_hash: [7; 32],
            connection_secret: [8; 32],
        };
        let bytes = layout::seal_fact(&connection, &responder_ephemeral_private_key)
            .expect("seal connection fact");
        Fact::new(FactScope::Local, 100, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ()> {
        ConnectionAuthenticator::authenticate(fact, &ProjectionContext::default())
    }

    fn is_invalid(fact: &Fact) -> bool {
        matches!(authenticate(fact), Authentication::Invalid(_))
    }

    #[test]
    fn authenticates_canonical_fact() {
        assert!(!is_invalid(&canonical_fact()));
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
