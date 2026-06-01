//! Key-request authenticator.
//!
//! POLICY. Authenticating a `key_request` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical key-request fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!
//! Admission scope (the requester's workspace) is interpretation the projector
//! owns, and requester/responder relationships are proven from other facts in
//! the projector.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::KeyRequestFact;

pub(crate) struct KeyRequestAuthenticator;

impl Authenticator for KeyRequestAuthenticator {
    type Authenticated = KeyRequestFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_key_request(fact))
    }
}

fn authenticate_key_request(fact: &Fact) -> Result<KeyRequestFact, String> {
    // 1. Layout.
    let request = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&request)?;
    Ok(request)
}
