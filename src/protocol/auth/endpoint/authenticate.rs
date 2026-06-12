//! Local-endpoint authenticator.
//!
//! POLICY. Authenticating a local `endpoint` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical endpoint fact — the layout
//!      re-derives both public keys from the stored private keys.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local identity secrets, not a signed shared proof, so there is no
//! fact-boundary signature. Admission scope (`Local`) is interpretation the
//! projector owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::EndpointFact;

pub(crate) fn authenticate(
    fact: &Fact,
    endpoint: EndpointFact,
    _context: &ProjectionContext,
) -> Result<EndpointFact, String> {
    prove_decoded_endpoint(fact, endpoint)
}

fn prove_decoded_endpoint(fact: &Fact, endpoint: EndpointFact) -> Result<EndpointFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::auth::endpoint::author::{create_local_endpoint, endpoint_fact};
    use crate::protocol::auth::endpoint::fact::EndpointFact;

    fn canonical_fact() -> Fact {
        endpoint_fact(100, create_local_endpoint()).expect("endpoint fact")
    }

    fn authenticate(fact: &Fact) -> Result<EndpointFact, String> {
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
