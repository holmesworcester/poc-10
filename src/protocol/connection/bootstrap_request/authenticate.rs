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
