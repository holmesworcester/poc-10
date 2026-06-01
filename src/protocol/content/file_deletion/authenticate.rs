//! Content-file-deletion authenticator.
//!
//! POLICY. Authenticating a `content_file_deletion` fact proves, over its signed
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical content-file-deletion fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!
//! Admission scope is unsigned local metadata, not part of these bytes, so the
//! workspace-scope check is interpretation the projector owns. The authority of
//! the signer, target file, and author user is proven from other facts, also in
//! the projector.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ContentFileDeletionFact;

pub(crate) struct ContentFileDeletionAuthenticator;

impl Authenticator for ContentFileDeletionAuthenticator {
    type Authenticated = ContentFileDeletionFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_file_deletion(fact))
    }
}

/// Prove a content-file-deletion fact authentic over its own bytes.
fn authenticate_file_deletion(fact: &Fact) -> Result<ContentFileDeletionFact, String> {
    // 1. Layout.
    let deletion = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&deletion)?;
    Ok(deletion)
}
