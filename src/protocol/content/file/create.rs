//! Deterministic constructors for content-file facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need command context, local capabilities,
//! or multi-fact orchestration belong in `commands.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::{Fact, FactId};
use crate::protocol::content::file::fact::{ContentFileFact, RootHash, SealedMetadata};
use crate::protocol::content::file::layout;

#[allow(clippy::too_many_arguments)]
pub fn signed_file_fact(
    workspace_id: FactId,
    created_at_ms: u64,
    message_id: FactId,
    author_user_id: FactId,
    signer_id: FactId,
    file_id: FactId,
    blob_bytes: u64,
    total_slices: u32,
    slice_bytes: u32,
    root_hash: RootHash,
    sealed_metadata: SealedMetadata,
    private_key: Ed25519PrivateKey,
) -> Result<Fact, String> {
    let signer_public_key = crypto::ed25519_public_key(&private_key);
    let mut file = ContentFileFact {
        workspace_id,
        created_at_ms,
        message_id,
        author_user_id,
        signer_id,
        signer_public_key,
        file_id,
        blob_bytes,
        total_slices,
        slice_bytes,
        root_hash,
        sealed_metadata,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let (_, signature) =
        crypto::ed25519_sign_canonical(&private_key, &layout::signing_bytes(&file)?);
    file.signature = signature;
    let bytes = layout::encode_fact(&file)?;
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        bytes,
    ))
}
