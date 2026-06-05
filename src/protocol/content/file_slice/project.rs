//! Poc-10 content-file-slice projector.
//!
//! POLICY. A content_file_slice is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped and its parent file selector
//!      and slice index decode from the canonical payload, and the slice
//!      signature verifies.
//!   2. CONTEXT. Projection waits for the parent file, verifies the BAO proof
//!      against that file's encrypted root hash, rejects out-of-range indexes,
//!      and watches parent file/message deletion context.
//!   3. MATERIALIZE. Live slices write one row containing the verified
//!      ciphertext and share the fact; deleted parents delete the slice row and
//!      purge this slice fact. AEAD opening stays in auth key-material code.

use crate::core::context::ContextNeed;
use crate::core::crypto;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::TableInsert;
use crate::core::intents::Value;
use crate::core::intents::{RowMutation, TableDeleteWhere};
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};

use crate::protocol::content::file;
use crate::protocol::content::file_deletion;
use crate::protocol::content::message;
use crate::protocol::content::message::fact::unix_minute_for;
use crate::protocol::content::message::project as message_project;
use crate::protocol::content::message_deletion;
use crate::protocol::content::purge::project as content_purge;
use crate::protocol::registry::read_models;
use crate::protocol::sync::shared_fact::project::{
    context_have_from_needs, retract_fact_from_sync, share_fact_with_sync,
};

use super::fact::ContentFileSliceFact;
use super::FILE_SLICE_ROWS;

pub(crate) const FILE_SLICE_KEY_COLUMNS: &[&str] = read_models::FILE_SLICES.key_columns;

pub fn content_file_slice_row(
    slice_fact_id: FactId,
    fact: &ContentFileSliceFact,
    ciphertext: Vec<u8>,
) -> TableInsert {
    read_models::FILE_SLICES.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::Bytes(fact.file_id.to_vec()),
        Value::U64(u64::from(fact.slice_index)),
        Value::Bytes(slice_fact_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(ciphertext),
    ])
}

/// Staged read pipeline for the file_slice fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "content::file_slice::Codec",
    authenticate: "content::file_slice::authenticate::ContentFileSliceAuthenticator",
    adapt: "content::file_slice::adapt::ContentFileSliceAdapter",
    project: "content::file_slice::project::ContentFileSliceProjector",
};

#[derive(Debug, Clone, Default)]
pub struct ContentFileSliceProjector;

impl ContentFileSliceProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentFileSliceProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::ContentFileSliceAuthenticator,
            super::adapt::ContentFileSliceAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<super::fact::ContentFileSliceFact> for ContentFileSliceProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        slice: super::fact::ContentFileSliceFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(slice.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Context and deletion gates.
        let file_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_file",
            scope.clone(),
            slice.file_id,
            slice.file_id,
        );
        let Some(parent) = context_payload(context, &file_need, "file slice parent")? else {
            return Ok(ProjectionOutput::new().need(file_need));
        };
        let file = message_project::decode_typed_fact(
            parent,
            file::TYPE_CONTENT_FILE,
            "file slice parent",
            file::decode_fact_payload,
        )
        .map_err(|_| "file slice parent context is not a content file".to_string())?;
        if parent.scope != scope {
            return Err("file slice parent scope does not match slice".to_string());
        }
        if file.workspace_id != slice.workspace_id {
            return Err("file slice parent workspace does not match slice".to_string());
        }
        if file.file_id != slice.file_id {
            return Err("file slice parent file_id does not match slice".to_string());
        }
        if file.signer_id != slice.signer_id || file.signer_public_key != slice.signer_public_key {
            return Err("file slice signer does not match parent file signer".to_string());
        }
        if slice.slice_index >= file.total_slices {
            return Err("file slice index is out of range for parent file".to_string());
        }
        let verified_ciphertext = verified_slice_ciphertext(&slice, &file)?;
        let message_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_message",
            scope.clone(),
            file.message_id,
            file.message_id,
        );
        let Some(message_payload) =
            context_payload(context, &message_need, "file slice message parent")?
        else {
            return Ok(ProjectionOutput::new().need(file_need).need(message_need));
        };
        let parent_message = message_project::decode_typed_fact(
            message_payload,
            message::TYPE_CONTENT_MESSAGE,
            "file slice message parent",
            message::decode_fact_payload,
        )?;
        if parent_message.workspace_id != slice.workspace_id {
            return Err("file slice message parent workspace does not match slice".to_string());
        }
        let file_deletion_need = content_purge::target_purged_need(
            fact.id,
            scope.clone(),
            parent_message.frontier_id,
            unix_minute_for(file.created_at_ms),
            parent.id,
        );
        let parent_deletion_need = content_purge::target_purged_need(
            fact.id,
            scope,
            parent_message.frontier_id,
            parent_message.minute,
            file.message_id,
        );
        if let Some(deletion) = context_payload(
            context,
            &parent_deletion_need,
            "file slice message parent deletion",
        )? {
            validate_message_deletion(
                deletion,
                file.workspace_id,
                parent_message.frontier_id,
                parent_message.minute,
                file.message_id,
                parent_message.author_user_id,
            )?;
            return Ok(retract_fact_from_sync(
                ProjectionOutput::new()
                    .need(file_need)
                    .need(message_need)
                    .need(file_deletion_need)
                    .need(parent_deletion_need)
                    .row_mutation(RowMutation::DeleteWhere(content_file_slice_delete(
                        slice.workspace_id,
                        slice.file_id,
                        slice.slice_index,
                    )))
                    .purge_self(fact.id),
                slice.workspace_id,
                fact.id,
                slice.created_at_ms,
            ));
        }
        if let Some(deletion) =
            context_payload(context, &file_deletion_need, "file slice parent deletion")?
        {
            validate_file_deletion(deletion, file.workspace_id, parent.id, file.author_user_id)?;
            return Ok(retract_fact_from_sync(
                ProjectionOutput::new()
                    .need(file_need)
                    .need(message_need)
                    .need(file_deletion_need)
                    .need(parent_deletion_need)
                    .row_mutation(RowMutation::DeleteWhere(content_file_slice_delete(
                        slice.workspace_id,
                        slice.file_id,
                        slice.slice_index,
                    )))
                    .purge_self(fact.id),
                slice.workspace_id,
                fact.id,
                slice.created_at_ms,
            ));
        }
        let context_have = context_have_from_needs(
            context,
            [
                &file_need,
                &message_need,
                &file_deletion_need,
                &parent_deletion_need,
            ],
        );

        // 3. Materialize.
        Ok(share_fact_with_sync(
            ProjectionOutput::new()
                .need(file_need)
                .need(message_need)
                .need(file_deletion_need)
                .need(parent_deletion_need)
                .row_mutation(RowMutation::InsertValues(content_file_slice_row(
                    fact.id,
                    &slice,
                    verified_ciphertext,
                ))),
            slice.workspace_id,
            fact,
            context_have,
        ))
    }
}

fn verified_slice_ciphertext(
    slice: &super::fact::ContentFileSliceFact,
    file: &file::fact::ContentFileFact,
) -> Result<Vec<u8>, String> {
    let (slice_start, slice_len) = encrypted_slice_range(file, slice.slice_index)?;
    let verified =
        crypto::bao_verify_slice(&file.root_hash, slice.proof.bytes(), slice_start, slice_len)
            .map_err(|err| format!("file slice bao proof verification failed: {err}"))?;
    if verified.len() != slice_len as usize {
        return Err("file slice bao proof length mismatch".to_string());
    }
    Ok(verified)
}

fn encrypted_slice_range(
    file: &file::fact::ContentFileFact,
    slice_index: u32,
) -> Result<(u64, u64), String> {
    let plaintext_start = u64::from(slice_index)
        .checked_mul(u64::from(file.slice_bytes))
        .ok_or_else(|| "file slice byte offset overflow".to_string())?;
    if plaintext_start >= file.blob_bytes {
        return Err("file slice byte offset is outside parent file".to_string());
    }
    let plaintext_len = file
        .blob_bytes
        .saturating_sub(plaintext_start)
        .min(u64::from(file.slice_bytes));
    let encrypted_len = plaintext_len
        .checked_add(crypto::XCHACHA20_POLY1305_TAG_BYTES as u64)
        .ok_or_else(|| "file slice encrypted length overflow".to_string())?;
    let encrypted_stride = u64::from(file.slice_bytes)
        .checked_add(crypto::XCHACHA20_POLY1305_TAG_BYTES as u64)
        .ok_or_else(|| "file slice encrypted stride overflow".to_string())?;
    let encrypted_start = u64::from(slice_index)
        .checked_mul(encrypted_stride)
        .ok_or_else(|| "file slice encrypted offset overflow".to_string())?;
    Ok((encrypted_start, encrypted_len))
}

fn context_payload<'a>(
    context: &'a ProjectionContext,
    need: &ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    context.payload_for_checked(need, label)
}

fn validate_file_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_file_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion = file_deletion::decode_fact_payload(payload.body()).map_err(|_| {
        "file slice parent deletion context is not a content file deletion".to_string()
    })?;
    if deletion.workspace_id != workspace_id {
        return Err("file slice parent deletion workspace does not match slice".to_string());
    }
    if deletion.target_file_id != target_file_id {
        return Err("file slice parent deletion target does not match parent file".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err(
            "file slice parent deletion author does not match parent file author".to_string(),
        );
    }
    Ok(())
}

fn validate_message_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_frontier_id: crate::core::facts::FactId,
    target_minute: u64,
    target_message_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion = message_project::decode_typed_fact(
        payload,
        message_deletion::TYPE_CONTENT_MESSAGE_DELETION,
        "file slice message parent deletion",
        message_deletion::decode_fact_payload,
    )?;
    if deletion.workspace_id != workspace_id {
        return Err("file slice message deletion workspace does not match slice".to_string());
    }
    if deletion.target_frontier_id != target_frontier_id {
        return Err("file slice message deletion frontier does not match parent".to_string());
    }
    if deletion.target_minute != target_minute {
        return Err("file slice message deletion minute does not match parent".to_string());
    }
    if deletion.target_message_id != target_message_id {
        return Err("file slice message deletion target does not match parent".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("file slice message deletion author does not match parent".to_string());
    }
    Ok(())
}

fn content_file_slice_delete(
    workspace_id: FactId,
    file_id: FactId,
    slice_index: u32,
) -> TableDeleteWhere {
    TableDeleteWhere {
        table: FILE_SLICE_ROWS,
        columns: FILE_SLICE_KEY_COLUMNS,
        values: vec![
            Value::Bytes(workspace_id.to_vec()),
            Value::Bytes(file_id.to_vec()),
            Value::U64(u64::from(slice_index)),
        ],
    }
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content file slice fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::content::file::fact::{ContentFileFact, SealedMetadata};
    use crate::protocol::content::file_slice::fact::{
        ContentFileSliceFact, FileSliceProof, FILE_SLICE_BAO_PROOF_BYTES,
        FILE_SLICE_CIPHERTEXT_BYTES,
    };

    fn file(root_hash: [u8; 32]) -> ContentFileFact {
        ContentFileFact {
            workspace_id: [1; 32],
            created_at_ms: 100,
            message_id: [2; 32],
            author_user_id: [3; 32],
            signer_id: [4; 32],
            signer_public_key: [5; 32],
            file_id: [6; 32],
            blob_bytes: 10,
            total_slices: 2,
            slice_bytes: 5,
            root_hash,
            sealed_metadata: SealedMetadata::new(b"sealed").expect("metadata"),
            signature: [7; crypto::ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn bao_proof_extracts_verified_ciphertext_for_slice_row() {
        let encrypted_blob: Vec<u8> = (0..42u8).collect();
        let (root_hash, outboard) = crypto::bao_outboard(&encrypted_blob).expect("outboard");
        let slice_start = 21;
        let slice_len = 21;
        let proof = crypto::bao_extract_slice(&encrypted_blob, &outboard, slice_start, slice_len)
            .expect("proof");
        let slice = ContentFileSliceFact {
            workspace_id: [1; 32],
            created_at_ms: 101,
            file_id: [6; 32],
            slice_index: 1,
            signer_id: [4; 32],
            signer_public_key: [5; 32],
            proof: FileSliceProof::new(&proof).expect("proof slot"),
            signature: [8; crypto::ED25519_SIGNATURE_BYTES],
        };

        let verified = verified_slice_ciphertext(&slice, &file(root_hash)).expect("verify");

        assert_eq!(verified, encrypted_blob[slice_start as usize..].to_vec());
    }

    #[test]
    fn bao_proof_rejects_wrong_root() {
        let encrypted_blob: Vec<u8> = (0..42u8).collect();
        let (_root_hash, outboard) = crypto::bao_outboard(&encrypted_blob).expect("outboard");
        let proof = crypto::bao_extract_slice(&encrypted_blob, &outboard, 0, 21).expect("proof");
        let slice = ContentFileSliceFact {
            workspace_id: [1; 32],
            created_at_ms: 101,
            file_id: [6; 32],
            slice_index: 0,
            signer_id: [4; 32],
            signer_public_key: [5; 32],
            proof: FileSliceProof::new(&proof).expect("proof slot"),
            signature: [8; crypto::ED25519_SIGNATURE_BYTES],
        };

        let err = verified_slice_ciphertext(&slice, &file([0xff; 32])).expect_err("reject");

        assert!(err.contains("bao proof verification failed"), "{err}");
    }

    #[test]
    fn proof_slot_fits_encrypted_slice_ranges() {
        let encrypted_blob = vec![0x42; FILE_SLICE_CIPHERTEXT_BYTES * 8];
        let (_root_hash, outboard) = crypto::bao_outboard(&encrypted_blob).expect("outboard");
        let proof = crypto::bao_extract_slice(
            &encrypted_blob,
            &outboard,
            FILE_SLICE_CIPHERTEXT_BYTES as u64,
            FILE_SLICE_CIPHERTEXT_BYTES as u64,
        )
        .expect("proof");

        assert!(
            proof.len() <= FILE_SLICE_BAO_PROOF_BYTES,
            "proof len {} exceeds fixed slot {}",
            proof.len(),
            FILE_SLICE_BAO_PROOF_BYTES
        );
    }

    #[test]
    fn slice_row_round_trips_ordered_key() {
        let fact = ContentFileSliceFact {
            workspace_id: [1; 32],
            created_at_ms: 77,
            file_id: [2; 32],
            slice_index: 5,
            signer_id: [6; 32],
            signer_public_key: [7; 32],
            proof: crate::protocol::content::file_slice::fact::FileSliceProof::new(&[0xdd; 16])
                .expect("proof"),
            signature: [0; crate::core::crypto::ED25519_SIGNATURE_BYTES],
        };
        let row = content_file_slice_row([9; 32], &fact, vec![0xcc; 16]);
        assert_eq!(row.table, FILE_SLICE_ROWS);
        assert_eq!(row.columns, read_models::FILE_SLICES.columns);
        assert_eq!(row.values[0], Value::Bytes(vec![1; 32]));
        assert_eq!(row.values[1], Value::Bytes(vec![2; 32]));
        assert_eq!(row.values[2], Value::U64(5));
        assert_eq!(row.values[3], Value::Bytes(vec![9; 32]));
        assert_eq!(row.values[5], Value::Bytes(vec![0xcc; 16]));
    }
}
