//! Connection-close authenticator.
//!
//! POLICY. Authenticating a `connection_close` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical connection-close fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   FIELDS. The named connection id is non-empty.
//!
//! It proves nothing else. Admission scope (`Local`) and the connection_response
//! context proof are interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ConnectionCloseFact;

pub(crate) struct ConnectionCloseAuthenticator;

impl Authenticator for ConnectionCloseAuthenticator {
    type Authenticated = ConnectionCloseFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_close(fact))
    }
}

fn authenticate_close(fact: &Fact) -> Result<ConnectionCloseFact, String> {
    // 1. Layout.
    let close = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // Intrinsic fields.
    if close.connection_id == [0; 32] {
        return Err("connection close connection_id cannot be empty".to_string());
    }
    Ok(close)
}
