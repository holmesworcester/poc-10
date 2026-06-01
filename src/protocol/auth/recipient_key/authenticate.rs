//! Recipient-key authenticator.
//!
//! POLICY. Authenticating a `recipient_key` fact proves, over its signed bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical recipient-key fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!   4. FIELDS. A recipient key cannot supersede itself
//!      (`previous_recipient_key_id != fact_id`).
//!
//! Admission scope is unsigned local metadata, so the workspace-scope check is
//! interpretation the projector owns. Supersession against an earlier key and
//! signer matching are proven from other facts, also in the projector.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::RecipientKeyFact;

pub(crate) struct RecipientKeyAuthenticator;

impl Authenticator for RecipientKeyAuthenticator {
    type Authenticated = RecipientKeyFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_recipient_key(fact))
    }
}

fn authenticate_recipient_key(fact: &Fact) -> Result<RecipientKeyFact, String> {
    // 1. Layout.
    let recipient = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&recipient)?;
    // 4. A recipient key cannot supersede itself.
    if recipient.previous_recipient_key_id == fact.id {
        return Err(
            "recipient key cannot supersede itself (previous_recipient_key_id == fact_id)"
                .to_string(),
        );
    }
    Ok(recipient)
}
