//! Membership connection-response authenticator.
//!
//! POLICY. Authenticating a `connection_response` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical membership connection-response
//!      fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   FIELDS. The response selector fields are non-empty, the two endpoints
//!   differ, and the response does not answer itself.
//!
//! It proves nothing else. Admission scope (`Local`), the close gate, request
//! context, the handshake transcript, and ephemeral material are all
//! interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{verify_fact_id, Authentication, Authenticator, ProjectionContext};
use crate::protocol::auth::endpoint;

use super::fact::ConnectionResponseFact;

pub(crate) struct ConnectionResponseAuthenticator;

impl Authenticator for ConnectionResponseAuthenticator {
    type Authenticated = ConnectionResponseFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        match authenticate_connection_response(fact, context) {
            Ok(response) => Authentication::Authenticated(
                crate::core::projectors::AuthenticatedFact::new(fact, response),
            ),
            Err(AuthenticationError::Need(need)) => Authentication::NeedsAuthentication(need),
            Err(AuthenticationError::Invalid(error)) => Authentication::Invalid(error),
        }
    }
}

enum AuthenticationError {
    Need(crate::core::context::ContextNeed),
    Invalid(String),
}

fn authenticate_connection_response(
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<ConnectionResponseFact, AuthenticationError> {
    // 1. Sealed layout and id.
    verify_fact_id(fact).map_err(AuthenticationError::Invalid)?;
    super::layout::validate_sealed_fact(fact.body()).map_err(AuthenticationError::Invalid)?;
    let endpoint_need = crate::core::context::ContextNeed::range(
        fact.id,
        "auth_local_endpoint",
        crate::core::facts::FactScope::Local,
        [0u8; 32],
        [0xffu8; 32],
    );
    let Some(endpoint_ctx) = context.payload_for(&endpoint_need) else {
        return Err(AuthenticationError::Need(endpoint_need));
    };
    let local_endpoint = endpoint::decode_fact_payload(endpoint_ctx.body()).map_err(|_| {
        AuthenticationError::Invalid(
            "membership connection response endpoint context is malformed".to_string(),
        )
    })?;
    let response = super::layout::open_fact(fact.body(), &local_endpoint)
        .map_err(AuthenticationError::Invalid)?;
    // Intrinsic fields.
    validate_response_fields(&response).map_err(AuthenticationError::Invalid)?;
    if response.from_endpoint == response.to_endpoint {
        return Err(AuthenticationError::Invalid(
            "membership connection response endpoints must differ".to_string(),
        ));
    }
    if response.request_id == fact.id {
        return Err(AuthenticationError::Invalid(
            "membership connection response cannot answer itself".to_string(),
        ));
    }
    Ok(response)
}

fn validate_response_fields(response: &ConnectionResponseFact) -> Result<(), String> {
    if response.from_endpoint == [0; 32] {
        return Err("membership connection response from_endpoint cannot be empty".to_string());
    }
    if response.to_endpoint == [0; 32] {
        return Err("membership connection response to_endpoint cannot be empty".to_string());
    }
    if response.request_id == [0; 32] {
        return Err("membership connection response request_id cannot be empty".to_string());
    }
    if response.initiator_ephemeral_secret_fact_id == [0; 32] {
        return Err(
            "membership connection response initiator_ephemeral_secret_fact_id cannot be empty"
                .to_string(),
        );
    }
    if response.responder_ephemeral_secret_fact_id == [0; 32] {
        return Err(
            "membership connection response responder_ephemeral_secret_fact_id cannot be empty"
                .to_string(),
        );
    }
    if response.responder_ephemeral_public_key == [0; 32] {
        return Err(
            "membership connection response responder_ephemeral_public_key cannot be empty"
                .to_string(),
        );
    }
    if response.handshake_hash == [0; 32] {
        return Err("membership connection response handshake_hash cannot be empty".to_string());
    }
    if response.connection_secret == [0; 32] {
        return Err("membership connection response connection_secret cannot be empty".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::connection::connection_response::fact::ConnectionResponseFact;
    use crate::protocol::connection::connection_response::layout;

    use super::ConnectionResponseAuthenticator;

    fn canonical_fact() -> Fact {
        let initiator_secret = [9; 32];
        let responder_ephemeral_private_key = [10; 32];
        let response = ConnectionResponseFact {
            from_endpoint: [1; 32],
            to_endpoint: crypto::x25519_public_key(&initiator_secret),
            request_id: [3; 32],
            initiator_ephemeral_secret_fact_id: [4; 32],
            responder_ephemeral_secret_fact_id: [5; 32],
            responder_ephemeral_public_key: crypto::x25519_public_key(
                &responder_ephemeral_private_key,
            ),
            handshake_hash: [7; 32],
            connection_secret: [8; 32],
        };
        let bytes = layout::seal_fact(&response, &responder_ephemeral_private_key)
            .expect("seal connection_response fact");
        Fact::new(FactScope::Local, 100, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ConnectionResponseFact> {
        ConnectionResponseAuthenticator::authenticate(fact, &ProjectionContext::default())
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
