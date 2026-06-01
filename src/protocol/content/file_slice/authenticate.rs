//! Content-file-slice authenticator.
//!
//! POLICY. Authenticating a `content_file_slice` fact proves, over its signed
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical content-file-slice fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!
//! Admission scope is unsigned local metadata, not part of these bytes, so the
//! workspace-scope check is interpretation the projector owns. The parent file,
//! the BAO proof over its root hash, and the deletion gates are proven from
//! other facts, also in the projector.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ContentFileSliceFact;

pub(crate) struct ContentFileSliceAuthenticator;

impl Authenticator for ContentFileSliceAuthenticator {
    type Authenticated = ContentFileSliceFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_file_slice(fact))
    }
}

/// Prove a content-file-slice fact authentic over its own bytes.
fn authenticate_file_slice(fact: &Fact) -> Result<ContentFileSliceFact, String> {
    // 1. Layout.
    let slice = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&slice)?;
    Ok(slice)
}
