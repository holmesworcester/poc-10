//! Key-wrap authenticator.
//!
//! POLICY. Authenticating a `key_wrap` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical key-wrap fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! A key wrap is the raw exception to natural fact signing: it carries no
//! signature field, so there is nothing to verify at the fact boundary. The
//! signer is proven from recipient/frontier/endpoint context, and admission
//! scope is unsigned local metadata — both are interpretation the projector
//! owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::KeyWrapFact;

pub(crate) struct KeyWrapAuthenticator;

impl Authenticator for KeyWrapAuthenticator {
    type Authenticated = KeyWrapFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_key_wrap(fact))
    }
}

fn authenticate_key_wrap(fact: &Fact) -> Result<KeyWrapFact, String> {
    // 1. Layout.
    let wrap = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(wrap)
}
