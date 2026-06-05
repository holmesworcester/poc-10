//! Deterministic constructors for content-reaction facts.
//!
//! This layer takes already-resolved semantic parameters plus the signer's
//! private key and returns the canonical, signed fact bytes. API and CLI
//! workflows that need command context, local capabilities, or multi-fact
//! orchestration belong in `commands.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::{Fact, FactId};
use crate::protocol::content::reaction::encode;
use crate::protocol::content::reaction::fact::{
    ContentReactionFact, ReactionCiphertext, REACTION_NONCE_BYTES,
};

#[allow(clippy::too_many_arguments)]
pub fn signed_reaction_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    target_message_id: FactId,
    author_user_id: FactId,
    signer_id: FactId,
    nonce: [u8; REACTION_NONCE_BYTES],
    ciphertext: ReactionCiphertext,
    private_key: Ed25519PrivateKey,
) -> Result<Fact, String> {
    let signer_public_key = crypto::ed25519_public_key(&private_key);
    let mut reaction = ContentReactionFact {
        workspace_id,
        created_at_ms,
        target_message_id,
        author_user_id,
        signer_id,
        signer_public_key,
        nonce,
        ciphertext,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let (_, signature) = crypto::ed25519_sign_canonical(
        &private_key,
        &crate::core::wire::encode_with_zeroed_trailing_field(
            &reaction,
            encode::encode_fact,
            crate::core::crypto::ED25519_SIGNATURE_BYTES,
        )?,
    );
    reaction.signature = signature;
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        encode::encode_fact(&reaction)?,
    ))
}
