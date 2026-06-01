//! Content-message authenticator.
//!
//! POLICY. Authenticating a `content_message` fact proves, over its signed bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical content-message envelope — right
//!      tag, fixed width, valid fields — through the family codec.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The author signature verifies over the canonical public
//!      envelope, which covers the ciphertext slot. The verifier key is embedded
//!      in the fact, so this needs no context.
//!
//! It proves nothing else. Admission scope is unsigned local metadata, not part
//! of these bytes, so the workspace-scope check is interpretation the projector
//! owns — that keeps the workspace-id format, its type, and the rule itself
//! behind the lens and the single ceiling projector, free to evolve. Decryption
//! of the message text likewise stays in the projector: the text key is secret
//! context and decryption yields read-model meaning. The authenticated payload
//! is the decoded fact; the projector proves scope, signer, author, deletion,
//! retention, and secret context and materializes rows.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ContentMessageFact;

pub(crate) struct ContentMessageAuthenticator;

impl Authenticator for ContentMessageAuthenticator {
    type Authenticated = ContentMessageFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_message(fact))
    }
}

/// Prove a content-message fact authentic over its own bytes.
///
/// Context-free, so the steps chain with `?`; `authenticate` maps the result to
/// an `Authentication` outcome.
fn authenticate_message(fact: &Fact) -> Result<ContentMessageFact, String> {
    // 1. Layout.
    let message = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&message)?;
    Ok(message)
}
