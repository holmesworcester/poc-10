//! Connection-close authenticator.
//!
//! POLICY. Authenticating a `connection_close` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical connection-close fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   FIELDS. The named connection id is non-empty.
//!
//! It proves nothing else. Admission scope (`Local`) and the connection_established
//! context proof are interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ConnectionCloseFact;

pub(crate) struct ConnectionCloseAuthenticator;

impl Authenticator for ConnectionCloseAuthenticator {
    type Authenticated = ConnectionCloseFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_close(fact))
    }
}

fn authenticate_close(fact: &Fact) -> Result<ConnectionCloseFact, String> {
    // 1. Layout.
    let close = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // Intrinsic fields.
    if close.connection_id == [0; 32] {
        return Err("connection close connection_id cannot be empty".to_string());
    }
    Ok(close)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::connection::close::fact::ConnectionCloseFact;
    use crate::protocol::connection::close::layout;

    use super::ConnectionCloseAuthenticator;

    fn canonical_fact() -> Fact {
        let close = ConnectionCloseFact {
            connection_id: [1; 32],
            closed_at_ms: 2,
        };
        let bytes = layout::encode_fact(&close).expect("encode connection_close fact");
        Fact::new(FactScope::Local, 100, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ConnectionCloseFact> {
        ConnectionCloseAuthenticator::authenticate(fact, &ProjectionContext::default())
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
