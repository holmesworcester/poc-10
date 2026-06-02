//! Connection fact-receipt authenticator.
//!
//! POLICY. Authenticating a `connection_fact_receipt` fact proves, over its
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical fact-receipt payload.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! Receipts are unsigned local evidence: there is no fact-boundary signature and
//! no intrinsic field rule. Admission scope (`Local`) is unsigned metadata, so
//! the local-scope check stays in the projector, as does publishing receipt
//! context for the received fact.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ConnectionFactReceipt;

pub(crate) struct ConnectionFactReceiptAuthenticator;

impl Authenticator for ConnectionFactReceiptAuthenticator {
    type Authenticated = ConnectionFactReceipt;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_fact_receipt(fact))
    }
}

fn authenticate_fact_receipt(fact: &Fact) -> Result<ConnectionFactReceipt, String> {
    // 1. Layout.
    let received = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(received)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::connection::fact_receipt::fact::{
        ConnectionFactReceipt, OriginAddr, RECEIVE_PATH_CONNECTION_RESPONSE,
    };
    use crate::protocol::connection::fact_receipt::layout;

    use super::ConnectionFactReceiptAuthenticator;

    fn canonical_fact() -> Fact {
        let receipt = ConnectionFactReceipt {
            received_fact_id: [1; 32],
            origin_addr: OriginAddr::new(b"127.0.0.1:41001").expect("origin"),
            local_endpoint_id: [2; 32],
            sender_endpoint_id: [3; 32],
            receive_path: RECEIVE_PATH_CONNECTION_RESPONSE,
            connection_id: Some([4; 32]),
            request_id: Some([6; 32]),
            frame_hash: [5; 32],
            received_at_local_ms: 1_700_000_001,
        };
        Fact::new(
            FactScope::Local,
            100,
            layout::encode_fact(&receipt).expect("encode receipt"),
        )
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ConnectionFactReceipt> {
        ConnectionFactReceiptAuthenticator::authenticate(fact, &ProjectionContext::default())
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
