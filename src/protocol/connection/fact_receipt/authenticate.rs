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
