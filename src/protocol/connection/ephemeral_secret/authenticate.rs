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
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ConnectionEphemeralSecretFact;

pub(crate) struct ConnectionEphemeralSecretAuthenticator;

impl Authenticator for ConnectionEphemeralSecretAuthenticator {
    type Authenticated = ConnectionEphemeralSecretFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_ephemeral_secret(fact))
    }
}

fn authenticate_ephemeral_secret(fact: &Fact) -> Result<ConnectionEphemeralSecretFact, String> {
    // 1. Layout.
    let secret = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // Intrinsic fields.
    if crypto::x25519_public_key(&secret.ephemeral_private_key) != secret.ephemeral_public_key {
        return Err("connection ephemeral public key does not match private key".to_string());
    }
    Ok(secret)
}
