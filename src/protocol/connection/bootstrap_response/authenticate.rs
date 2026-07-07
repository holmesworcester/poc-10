//! Connection-response authenticator.
//!
//! POLICY. Authenticating a `connection_response` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical connection-response fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   FIELDS. The response selector fields are non-empty, the two endpoints
//!   differ, and the response does not answer itself.
//!
//! It proves nothing else. Admission scope (`Local`), the close gate, request
//! and invite-secret context, the handshake transcript, and ephemeral material
//! are all interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::BootstrapResponseFact;

pub(crate) struct BootstrapResponseAuthenticator;

impl Authenticator for BootstrapResponseAuthenticator {
    type Authenticated = BootstrapResponseFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_bootstrap_response(fact))
    }
}

fn authenticate_bootstrap_response(fact: &Fact) -> Result<BootstrapResponseFact, String> {
    // 1. Layout.
    let response = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // Intrinsic fields.
    validate_response_fields(&response)?;
    if response.from_endpoint == response.to_endpoint {
        return Err("connection response endpoints must differ".to_string());
    }
    if response.request_id == fact.id {
        return Err("connection response cannot answer itself".to_string());
    }
    Ok(response)
}

fn validate_response_fields(response: &BootstrapResponseFact) -> Result<(), String> {
    if response.from_endpoint == [0; 32] {
        return Err("connection response from_endpoint cannot be empty".to_string());
    }
    if response.to_endpoint == [0; 32] {
        return Err("connection response to_endpoint cannot be empty".to_string());
    }
    if response.request_id == [0; 32] {
        return Err("connection response request_id cannot be empty".to_string());
    }
    if response.invite_secret_fact_id == [0; 32] {
        return Err("connection response invite_secret_fact_id cannot be empty".to_string());
    }
    if response.initiator_ephemeral_secret_fact_id == [0; 32] {
        return Err(
            "connection response initiator_ephemeral_secret_fact_id cannot be empty".to_string(),
        );
    }
    if response.responder_ephemeral_secret_fact_id == [0; 32] {
        return Err(
            "connection response responder_ephemeral_secret_fact_id cannot be empty".to_string(),
        );
    }
    if response.responder_ephemeral_public_key == [0; 32] {
        return Err(
            "connection response responder_ephemeral_public_key cannot be empty".to_string(),
        );
    }
    if response.handshake_hash == [0; 32] {
        return Err("connection response handshake_hash cannot be empty".to_string());
    }
    if response.connection_secret == [0; 32] {
        return Err("connection response connection_secret cannot be empty".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::connection::bootstrap_response::fact::BootstrapResponseFact;
    use crate::protocol::connection::bootstrap_response::layout;

    use super::BootstrapResponseAuthenticator;

    fn canonical_fact() -> Fact {
        let response = BootstrapResponseFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            request_id: [3; 32],
            invite_secret_fact_id: [4; 32],
            initiator_ephemeral_secret_fact_id: [5; 32],
            responder_ephemeral_secret_fact_id: [6; 32],
            responder_ephemeral_public_key: [7; 32],
            handshake_hash: [8; 32],
            connection_secret: [9; 32],
        };
        let bytes = layout::encode_fact(&response).expect("encode bootstrap_response fact");
        Fact::new(FactScope::Local, 100, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, BootstrapResponseFact> {
        BootstrapResponseAuthenticator::authenticate(fact, &ProjectionContext::default())
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
