//! Cascade test-fact authenticator.
//!
//! POLICY. Authenticating a `cascade_test_fact` proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical cascade test fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   FIELDS. The body timestamp equals the outer fact timestamp.
//!
//! Cascade facts carry no fact-boundary signature; declared dependencies are
//! CONTEXT the projector proves from other facts, and publishing completion
//! context is interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::CascadeTestFact;

pub(crate) struct CascadeTestFactAuthenticator;

impl Authenticator for CascadeTestFactAuthenticator {
    type Authenticated = CascadeTestFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_cascade_test_fact(fact))
    }
}

fn authenticate_cascade_test_fact(fact: &Fact) -> Result<CascadeTestFact, String> {
    // 1. Layout.
    let decoded = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // FIELDS.
    if decoded.timestamp != fact.timestamp {
        return Err("cascade fact timestamp does not match fact timestamp".to_string());
    }
    Ok(decoded)
}
