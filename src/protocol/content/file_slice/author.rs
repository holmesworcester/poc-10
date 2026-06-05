//! Deterministic constructors for content-file-slice facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need command context, local capabilities,
//! or multi-fact orchestration belong in `commands.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::{Fact, FactId};
use crate::protocol::content::file_slice::encode;
use crate::protocol::content::file_slice::fact::{ContentFileSliceFact, FileSliceProof, SignerId};

#[allow(clippy::too_many_arguments)]
pub fn signed_file_slice_fact(
    workspace_id: FactId,
    created_at_ms: u64,
    file_id: FactId,
    slice_index: u32,
    signer_id: SignerId,
    proof: FileSliceProof,
    private_key: &Ed25519PrivateKey,
) -> Result<Fact, String> {
    let signer_public_key = crypto::ed25519_public_key(private_key);
    let mut slice = ContentFileSliceFact {
        workspace_id,
        created_at_ms,
        file_id,
        slice_index,
        signer_id,
        signer_public_key,
        proof,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let (_, signature) = crypto::ed25519_sign_canonical(
        private_key,
        &crate::protocol::canonical::encode_with_zeroed_trailing_signature(
            &slice,
            encode::encode_fact,
        )?,
    );
    slice.signature = signature;
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        encode::encode_fact(&slice)?,
    ))
}
