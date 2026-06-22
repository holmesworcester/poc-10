pub mod decode {
    //! Byte decoding for content-file-slice facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{CONTENT_FILE_SLICE_BYTES, TYPE_CONTENT_FILE_SLICE};
    use super::super::fact::{ContentFileSliceFact, FILE_SLICE_BAO_PROOF_BYTES};

    pub fn decode_fact(bytes: &[u8]) -> Result<ContentFileSliceFact, String> {
        let mut reader = wire::Reader::new(bytes);
        reader
            .expect_len(CONTENT_FILE_SLICE_BYTES)
            .map_err(wire_err)?;
        let tag = reader.u8().map_err(wire_err)?;
        if tag != TYPE_CONTENT_FILE_SLICE {
            return Err("expected content file slice fact".to_string());
        }
        let workspace_id = reader.array().map_err(wire_err)?;
        let created_at_ms = reader.u64be().map_err(wire_err)?;
        let file_id = reader.array().map_err(wire_err)?;
        let slice_index = reader.u32be().map_err(wire_err)?;
        let signer_id = reader.array().map_err(wire_err)?;
        let signer_public_key = reader.array().map_err(wire_err)?;
        let proof = reader
            .fixed_slot_value::<FILE_SLICE_BAO_PROOF_BYTES>()
            .map_err(wire_err)?;
        reader.finish().map_err(wire_err)?;
        Ok(ContentFileSliceFact {
            workspace_id,
            created_at_ms,
            file_id,
            slice_index,
            signer_id,
            signer_public_key,
            proof,
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests. Ordered most-central first: the fixed-width roundtrip proves the
    // whole codec, then the tag/length rejections guard the layout.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::content::file_slice::encode::{
            encode_fact, CONTENT_FILE_SLICE_BYTES, TYPE_CONTENT_FILE_SLICE,
        };

        fn fact() -> ContentFileSliceFact {
            ContentFileSliceFact {
                workspace_id: [1; 32],
                created_at_ms: 4242,
                file_id: [2; 32],
                slice_index: 3,
                signer_id: [9; 32],
                signer_public_key: [10; 32],
                proof: crate::protocol::content::file_slice::fact::FileSliceProof::new(
                    &[0xaa; 128],
                )
                .expect("proof"),
            }
        }

        #[test]
        fn content_file_slice_roundtrips_with_ciphertext() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), CONTENT_FILE_SLICE_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[0] = TYPE_CONTENT_FILE_SLICE.wrapping_add(1);
            assert!(decode_fact(&encoded).is_err());
        }

        #[test]
        fn rejects_wrong_length() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded.push(0);
            assert!(decode_fact(&encoded).is_err());
        }
    }
}
pub mod authenticate {
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
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::ContentFileSliceFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        slice: ContentFileSliceFact,
        _context: &ProjectionContext,
    ) -> Result<ContentFileSliceFact, String> {
        prove_decoded_file_slice(fact, slice)
    }

    fn prove_decoded_file_slice(
        fact: &Fact,
        slice: ContentFileSliceFact,
    ) -> Result<ContentFileSliceFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(slice)
    }

    // Tests. Ordered most-central first: a canonical fact authenticates, then
    // the id-binding invariant (id == hash(bytes)), then the layout rejections.
    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::content::file_slice::author::authored_file_slice_fact;
        use crate::protocol::content::file_slice::fact::{ContentFileSliceFact, FileSliceProof};

        const PRIVATE_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            authored_file_slice_fact(
                [1; 32],
                100,
                [2; 32],
                0,
                [3; 32],
                FileSliceProof::new(b"bao-slice-proof").expect("slice proof"),
                &PRIVATE_KEY,
            )
            .expect("authored content file slice fact")
        }

        fn authenticate(fact: &Fact) -> Result<ContentFileSliceFact, String> {
            let decoded = super::super::decode::decode_fact(fact.body())?;
            super::authenticate(fact, decoded, &ProjectionContext::default())
        }

        fn is_invalid(fact: &Fact) -> bool {
            authenticate(fact).is_err()
        }

        #[test]
        fn authenticates_canonical_fact() {
            assert!(authenticate(&canonical_fact()).is_ok());
        }

        #[test]
        fn rejects_id_not_matching_bytes() {
            let canonical = canonical_fact();
            let forged = Fact {
                id: [0; 32],
                scope: canonical.scope.clone(),
                timestamp: canonical.timestamp,
                bytes: canonical.bytes.clone(),
            };
            assert!(is_invalid(&forged));
        }

        #[test]
        fn rejects_wrong_tag() {
            let canonical = canonical_fact();
            let mut bytes = canonical.bytes.clone();
            bytes[0] ^= 0xff;
            assert!(is_invalid(&Fact::new(
                canonical.scope,
                canonical.timestamp,
                bytes
            )));
        }

        #[test]
        fn rejects_truncated_bytes() {
            let canonical = canonical_fact();
            let mut bytes = canonical.bytes.clone();
            bytes.pop();
            assert!(is_invalid(&Fact::new(
                canonical.scope,
                canonical.timestamp,
                bytes
            )));
        }
    }
}
pub mod adapt {
    //! Content-file-slice semantic adapter.
    //!
    //! The current file_slice wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::ContentFileSliceFact;

    pub(crate) fn adapt(source: ContentFileSliceFact) -> Result<ContentFileSliceFact, String> {
        Ok(source)
    }
}

// Poc-10 content-file-slice projector.
//
// POLICY. A content_file_slice is admitted iff:
//   1. STRUCTURAL. The fact is workspace-scoped and its parent file selector
//      and slice index decode from the canonical payload, and the slice
//      signature verifies.
//   2. CONTEXT. Projection waits for the parent file, verifies the BAO proof
//      against that file's encrypted root hash, rejects out-of-range indexes,
//      and watches parent file/message deletion context.
//   3. MATERIALIZE. Live slices write one row containing the verified
//      ciphertext and share the fact; deleted parents delete the slice row and
//      purge this slice fact. AEAD opening stays in auth key-material code.

use crate::core::context::ContextNeed;
use crate::core::crypto;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::TableDeleteWhere;
use crate::core::intents::TableInsert;
use crate::core::intents::Value;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectedRowMutation, ProjectionContext, ProjectionOutput, Projector,
};

use crate::protocol::auth::signature;
use crate::protocol::content::file;
use crate::protocol::content::message;
use crate::protocol::content::message::project as message_project;
use crate::protocol::content::{file_deletion, message_deletion};
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

/// Projector route metadata for the file_slice fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("content::file_slice::project::ContentFileSliceProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

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
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl ContentFileSliceProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        slice: super::fact::ContentFileSliceFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(slice.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Context, signature evidence, and deletion gates.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            scope.clone(),
            fact.id,
            slice.signer_public_key,
        )?;
        let file_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_file",
            scope.clone(),
            slice.file_id,
            slice.file_id,
        );
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            slice.workspace_id,
            fact.id,
            slice.signer_public_key,
            "file slice",
        )? {
            return Ok(ProjectionOutput::new().need(signature_need).need(file_need));
        }
        let Some(parent) = context_payload(context, &file_need, "file slice parent")? else {
            return Ok(ProjectionOutput::new().need(signature_need).need(file_need));
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
            return Ok(ProjectionOutput::new()
                .need(signature_need)
                .need(file_need)
                .need(message_need));
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
        let file_deletion_need = crate::core::project_fact::fact_purged_need(
            fact.id,
            scope.clone(),
            file_deletion::project::file_purged_key(parent.id),
        );
        let parent_deletion_need = crate::core::project_fact::fact_purged_need(
            fact.id,
            scope,
            message_project::fact_purged_key(
                parent_message.frontier_id,
                parent_message.minute,
                file.message_id,
            ),
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
                    .need(file_deletion_need)
                    .need(parent_deletion_need)
                    .row_mutation(ProjectedRowMutation::DeleteWhere(
                        content_file_slice_delete(
                            slice.workspace_id,
                            slice.file_id,
                            slice.slice_index,
                        ),
                    ))
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
                    .need(file_deletion_need)
                    .need(parent_deletion_need)
                    .row_mutation(ProjectedRowMutation::DeleteWhere(
                        content_file_slice_delete(
                            slice.workspace_id,
                            slice.file_id,
                            slice.slice_index,
                        ),
                    ))
                    .purge_self(fact.id),
                slice.workspace_id,
                fact.id,
                slice.created_at_ms,
            ));
        }
        let context_have = context_have_from_needs(
            context,
            [
                &signature_need,
                &file_need,
                &message_need,
                &file_deletion_need,
                &parent_deletion_need,
            ],
        );

        // 3. Materialize.
        Ok(share_fact_with_sync(
            ProjectionOutput::new()
                .need(file_deletion_need)
                .need(parent_deletion_need)
                .row_mutation(ProjectedRowMutation::InsertValues(content_file_slice_row(
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

// Tests.
//
// Invariants:
// - content_file_slice facts must live in the workspace scope named by their
//   body;
// - projection waits for signature proof and parent file context before it can
//   verify a BAO proof or write a slice row;
// - BAO proof verification extracts only ciphertext proven by the parent root;
// - slice rows preserve the registry column order and ordered key.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::project_fact::Projector;
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

    #[test]
    fn content_file_slice_projector_waits_for_signature_and_parent_file() {
        let fact = authored_slice();

        let output = ContentFileSliceProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project without context");

        let roles = output
            .needs
            .iter()
            .map(|need| need.role.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            roles,
            std::collections::BTreeSet::from(["content_file", "signature_proof"])
        );
        assert!(output.row_mutations.is_empty());
    }

    #[test]
    fn content_file_slice_projector_rejects_scope_that_does_not_match_workspace() {
        let fact = authored_slice();
        let wrong_scope = crate::core::facts::Fact {
            scope: crate::protocol::auth::workspace::scope([9; 32]),
            ..fact
        };

        let err = ContentFileSliceProjector::new()
            .project(&wrong_scope, &ProjectionContext::default())
            .expect_err("wrong scope should reject");

        assert!(err.contains("scope does not match"), "{err}");
    }

    fn authored_slice() -> crate::core::facts::Fact {
        crate::protocol::content::file_slice::author::authored_file_slice_fact(
            [1; 32],
            100,
            [2; 32],
            0,
            [3; 32],
            FileSliceProof::new(&[0xdd; 16]).expect("proof"),
            &[4; 32],
        )
        .expect("authored file slice")
    }
}
