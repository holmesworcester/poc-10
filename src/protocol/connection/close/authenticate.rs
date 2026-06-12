//! Connection-close authenticator.
//!
//! POLICY. Authenticating a `connection_close` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical connection-close fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   FIELDS. The named connection id is non-empty.
//!
//! It proves nothing else. Admission scope (`Local`) and the connection
//! context proof are interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::ConnectionCloseFact;

pub(crate) fn authenticate(
    fact: &Fact,
    close: ConnectionCloseFact,
    _context: &ProjectionContext,
) -> Result<ConnectionCloseFact, String> {
    prove_decoded_close(fact, close)
}

fn prove_decoded_close(
    fact: &Fact,
    close: ConnectionCloseFact,
) -> Result<ConnectionCloseFact, String> {
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
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::connection::close::encode;
    use crate::protocol::connection::close::fact::ConnectionCloseFact;

    fn canonical_fact() -> Fact {
        let close = ConnectionCloseFact {
            connection_id: [1; 32],
            closed_at_ms: 2,
        };
        let bytes = encode::encode_fact(&close).expect("encode connection_close fact");
        Fact::new(FactScope::Local, 100, bytes)
    }

    fn authenticate(fact: &Fact) -> Result<ConnectionCloseFact, String> {
        let decoded = super::super::decode::decode_fact(fact.body())?;
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
