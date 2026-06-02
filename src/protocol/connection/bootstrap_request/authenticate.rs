//! Connection-request authenticator.
//!
//! POLICY. Authenticating a `connection_request` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical connection-request fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   FIELDS. The request selector fields are non-empty and the two endpoints
//!   differ.
//!
//! It proves nothing else. Admission scope (local or global) is unsigned local
//! metadata, and the invite signature is proven from invite-secret context, so
//! both stay in the projector along with branch-specific context and
//! materialization.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::BootstrapRequestFact;

pub(crate) struct BootstrapRequestAuthenticator;

impl Authenticator for BootstrapRequestAuthenticator {
    type Authenticated = BootstrapRequestFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_bootstrap_request(fact))
    }
}

fn authenticate_bootstrap_request(fact: &Fact) -> Result<BootstrapRequestFact, String> {
    // 1. Layout.
    let request = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // Intrinsic fields.
    validate_request_fields(&request)?;
    if request.from_endpoint == request.to_endpoint {
        return Err("connection request endpoints must differ".to_string());
    }
    Ok(request)
}

fn validate_request_fields(request: &BootstrapRequestFact) -> Result<(), String> {
    if request.from_endpoint == [0; 32] {
        return Err("connection request from_endpoint cannot be empty".to_string());
    }
    if request.to_endpoint == [0; 32] {
        return Err("connection request to_endpoint cannot be empty".to_string());
    }
    if request.invite_fact_id == [0; 32] {
        return Err("connection request invite_fact_id cannot be empty".to_string());
    }
    if request.bootstrap_hash == [0; 32] {
        return Err("connection request bootstrap_hash cannot be empty".to_string());
    }
    if request.invite_secret_fact_id == [0; 32] {
        return Err("connection request invite_secret_fact_id cannot be empty".to_string());
    }
    if request.initiator_ephemeral_secret_fact_id == [0; 32] {
        return Err(
            "connection request initiator_ephemeral_secret_fact_id cannot be empty".to_string(),
        );
    }
    if request.initiator_ephemeral_public_key == [0; 32] {
        return Err(
            "connection request initiator_ephemeral_public_key cannot be empty".to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::connection::bootstrap_request::fact::BootstrapRequestFact;
    use crate::protocol::connection::bootstrap_request::layout;

    use super::BootstrapRequestAuthenticator;

    fn canonical_fact() -> Fact {
        let request = BootstrapRequestFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            nonce: [3; 32],
            invite_fact_id: [4; 32],
            bootstrap_hash: [5; 32],
            invite_signature: [6; crate::core::crypto::ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: [7; 32],
            initiator_ephemeral_secret_fact_id: [8; 32],
            initiator_ephemeral_public_key: [9; 32],
            from_listen_addr: None,
            to_listen_addr: None,
        };
        let bytes = layout::encode_fact(&request).expect("encode bootstrap_request fact");
        Fact::new(FactScope::Global, 100, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, BootstrapRequestFact> {
        BootstrapRequestAuthenticator::authenticate(fact, &ProjectionContext::default())
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
