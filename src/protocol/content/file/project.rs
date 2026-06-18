pub mod decode {
    //! Byte decoding for content-file facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{CONTENT_FILE_BYTES, TYPE_CONTENT_FILE};
    use super::super::fact::{ContentFileFact, SEALED_METADATA_BYTES};

    pub fn decode_fact(bytes: &[u8]) -> Result<ContentFileFact, String> {
        let mut reader = wire::Reader::new(bytes);
        reader.expect_len(CONTENT_FILE_BYTES).map_err(wire_err)?;
        let tag = reader.u8().map_err(wire_err)?;
        if tag != TYPE_CONTENT_FILE {
            return Err("expected content file fact".to_string());
        }
        let workspace_id = reader.array().map_err(wire_err)?;
        let created_at_ms = reader.u64be().map_err(wire_err)?;
        let message_id = reader.array().map_err(wire_err)?;
        let author_user_id = reader.array().map_err(wire_err)?;
        let signer_id = reader.array().map_err(wire_err)?;
        let signer_public_key = reader.array().map_err(wire_err)?;
        let file_id = reader.array().map_err(wire_err)?;
        let blob_bytes = reader.u64be().map_err(wire_err)?;
        let total_slices = reader.u32be().map_err(wire_err)?;
        let slice_bytes = reader.u32be().map_err(wire_err)?;
        let root_hash = reader.array().map_err(wire_err)?;
        let sealed_metadata = reader
            .fixed_slot_value::<SEALED_METADATA_BYTES>()
            .map_err(wire_err)?;
        reader.finish().map_err(wire_err)?;
        Ok(ContentFileFact {
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
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::content::file::encode::{
            encode_fact, CONTENT_FILE_BYTES, TYPE_CONTENT_FILE,
        };
        use crate::protocol::content::file::fact::FILE_ROOT_HASH_BYTES;

        fn fact() -> ContentFileFact {
            ContentFileFact {
                workspace_id: [1; 32],
                created_at_ms: 12345,
                message_id: [2; 32],
                author_user_id: [3; 32],
                signer_id: [9; 32],
                signer_public_key: [10; 32],
                file_id: [4; 32],
                blob_bytes: 1_048_576,
                total_slices: 4,
                slice_bytes: 262_144,
                root_hash: [5; FILE_ROOT_HASH_BYTES],
                sealed_metadata: crate::protocol::content::file::fact::SealedMetadata::new(
                    b"sealed-filename-and-mime",
                )
                .expect("metadata"),
            }
        }

        #[test]
        fn content_file_roundtrips_with_sealed_metadata() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), CONTENT_FILE_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[0] = TYPE_CONTENT_FILE.wrapping_add(1);
            assert!(decode_fact(&encoded).is_err());
        }

        #[test]
        fn rejects_wrong_length() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded.pop();
            assert!(decode_fact(&encoded).is_err());
        }
    }
}
pub mod authenticate {
    //! Content-file authenticator.
    //!
    //! POLICY. Authenticating a `content_file` fact proves, over its canonical bytes
    //! alone:
    //!   1. LAYOUT. The bytes decode to a canonical content-file descriptor.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!   4. FIELDS. The selector ids are non-zero and the blob/slice descriptor is
    //!      internally consistent: size within the limit, slice count and budget
    //!      matching the fixed slot and the blob-bytes ceiling.
    //!
    //! Admission scope is unsigned local metadata, not part of these bytes, so the
    //! workspace-scope check is interpretation the projector owns. The parent
    //! message, deletion gates, and author are proven from other facts, also in the
    //! projector.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::MAX_FILE_BYTES;
    use crate::protocol::content::file_slice::fact::FILE_SLICE_PLAINTEXT_BYTES;

    pub(crate) fn authenticate(
        fact: &Fact,
        file: super::super::fact::ContentFileFact,
        _context: &ProjectionContext,
    ) -> Result<super::super::fact::ContentFileFact, String> {
        prove_decoded_file(fact, file)
    }

    fn prove_decoded_file(
        fact: &Fact,
        file: super::super::fact::ContentFileFact,
    ) -> Result<super::super::fact::ContentFileFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        // 4. Intrinsic descriptor fields.
        validate_file_fields(&file)?;
        Ok(file)
    }

    pub(super) fn validate_file_fields(
        file: &super::super::fact::ContentFileFact,
    ) -> Result<(), String> {
        validate_id("file workspace_id", &file.workspace_id)?;
        validate_id("file message_id", &file.message_id)?;
        validate_id("file author_user_id", &file.author_user_id)?;
        validate_id("file file_id", &file.file_id)?;
        if file.blob_bytes > MAX_FILE_BYTES {
            return Err("file size exceeds the 10 GiB limit".to_string());
        }
        if file.blob_bytes == 0 {
            if file.total_slices != 0 {
                return Err("zero-byte file must declare zero slices".to_string());
            }
            return Ok(());
        }
        if file.total_slices == 0 {
            return Err("non-empty file must declare at least one slice".to_string());
        }
        if file.slice_bytes == 0 {
            return Err("non-empty file must declare a slice budget".to_string());
        }
        if file.slice_bytes != FILE_SLICE_PLAINTEXT_BYTES as u32 {
            return Err("file slice budget must match the fixed file-slice slot".to_string());
        }
        let expected: u32 = file
            .blob_bytes
            .div_ceil(file.slice_bytes as u64)
            .try_into()
            .map_err(|_| "slice count overflows u32".to_string())?;
        if file.total_slices != expected {
            return Err(format!(
                "total_slices {} does not match blob_bytes / slice_bytes ceiling {}",
                file.total_slices, expected
            ));
        }
        Ok(())
    }

    fn validate_id(name: &str, id: &[u8; 32]) -> Result<(), String> {
        if id.iter().all(|byte| *byte == 0) {
            return Err(format!("{name} cannot be empty"));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::content::file::author::authored_file_fact;
        use crate::protocol::content::file::fact::{ContentFileFact, SealedMetadata};

        const PRIVATE_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            authored_file_fact(
                [1; 32],
                100,
                [2; 32],
                [3; 32],
                [4; 32],
                [5; 32],
                1_048_576,
                4,
                262_144,
                [6; 32],
                SealedMetadata::new(b"sealed-filename-and-mime").expect("sealed metadata"),
                PRIVATE_KEY,
            )
            .expect("authored content file fact")
        }

        fn authenticate(fact: &Fact) -> Result<ContentFileFact, String> {
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
    }
}
pub mod adapt {
    //! Content-file semantic adapter.
    //!
    //! The current file wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::ContentFileFact;

    pub(crate) fn adapt(source: ContentFileFact) -> Result<ContentFileFact, String> {
        Ok(source)
    }
}

// Content-file projector.
//
// POLICY. A content_file is admitted iff:
//   1. STRUCTURAL. The fact is workspace-scoped, signed, has valid descriptor
//      fields, and contains a content_file payload.
//   2. CONTEXT. Projection waits for signer, parent content message, deletion,
//      parent deletion, and author context; deletion context removes the
//      descriptor row and purges this file fact.
//   3. MATERIALIZE. Live files publish file/exact-fact offers, write the
//      descriptor row, and share the fact. File bytes remain slice facts.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::Value;
use crate::core::intents::{RowMutation, TableDeleteWhere, TableInsert};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};

use crate::protocol::auth::signature;
use crate::protocol::content::message::project::{self, FactSigner};
use crate::protocol::content::{file_deletion, message, message_deletion};
use crate::protocol::registry::read_models;
use crate::protocol::sync::shared_fact::project::{
    context_have_from_optional_needs, retract_fact_from_sync, share_fact_with_sync,
};

use super::fact::ContentFileFact;
use super::{FILE_KEY_COLUMNS, FILE_ROWS};

/// Projector route metadata for the file fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("content::file::project::ContentFileProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

fn content_file_row(file_fact_id: FactId, fact: &ContentFileFact) -> TableInsert {
    read_models::CONTENT_FILES.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::Bytes(file_fact_id.to_vec()),
        Value::Bytes(fact.message_id.to_vec()),
        Value::Bytes(fact.file_id.to_vec()),
        Value::Bytes(fact.author_user_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(fact.root_hash.to_vec()),
        Value::U64(fact.blob_bytes),
        Value::U64(u64::from(fact.total_slices)),
        Value::U64(u64::from(fact.slice_bytes)),
        Value::Bytes(fact.sealed_metadata.bytes().to_vec()),
        Value::Bool(false),
    ])
}

#[derive(Debug, Clone, Default)]
pub struct ContentFileProjector;

impl ContentFileProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentFileProjector {
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

impl ContentFileProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        file: super::fact::ContentFileFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(file.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Context, signature evidence, and deletion gates.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            scope.clone(),
            fact.id,
            file.signer_public_key,
        )?;
        let signer_need = project::signer_need(fact.id, file.workspace_id, file.signer_id);
        let parent_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_message",
            scope.clone(),
            file.message_id,
            file.message_id,
        );
        let author_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_user",
            crate::core::facts::FactScope::Global,
            file.author_user_id,
            file.author_user_id,
        );
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            file.workspace_id,
            fact.id,
            file.signer_public_key,
            "file",
        )? {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(parent_need),
                Some(author_need),
            ]));
        }
        if !project::validate_signer_context(
            context,
            &signer_need,
            FactSigner {
                signer_id: file.signer_id,
                signer_public_key: file.signer_public_key,
            },
            file.workspace_id,
            Some(file.author_user_id),
            "file",
        )? {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(parent_need),
                Some(author_need),
                None,
            ]));
        }
        let Some(parent_payload) = context_payload(context, &parent_need, "file parent")? else {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(parent_need),
                Some(author_need),
            ]));
        };
        let parent = parent_message_context(
            parent_payload,
            &scope,
            file.workspace_id,
            file.message_id,
            "file parent",
        )?;
        let file_deletion_need = crate::core::project_fact::fact_purged_need(
            fact.id,
            scope.clone(),
            project::fact_purged_key(
                parent.message.frontier_id,
                message::fact::unix_minute_for(file.created_at_ms),
                fact.id,
            ),
        );
        let parent_deletion_need = crate::core::project_fact::fact_purged_need(
            fact.id,
            scope.clone(),
            project::fact_purged_key(
                parent.message.frontier_id,
                parent.message.minute,
                file.message_id,
            ),
        );
        if let Some(deletion) = context_payload(context, &file_deletion_need, "file deletion")? {
            validate_file_deletion(deletion, file.workspace_id, fact.id, file.author_user_id)?;
            return Ok(retract_fact_from_sync(
                delete_file_projection(file.workspace_id, fact.id)
                    .need(signature_need)
                    .need(parent_need)
                    .need(file_deletion_need)
                    .need(parent_deletion_need)
                    .purge_self(fact.id),
                file.workspace_id,
                fact.id,
                file.created_at_ms,
            ));
        }
        if let Some(deletion) =
            context_payload(context, &parent_deletion_need, "file parent deletion")?
        {
            validate_message_deletion(
                deletion,
                file.workspace_id,
                parent.message.frontier_id,
                parent.message.minute,
                file.message_id,
                parent.message.author_user_id,
            )?;
            return Ok(retract_fact_from_sync(
                delete_file_projection(file.workspace_id, fact.id)
                    .need(signature_need)
                    .need(file_deletion_need)
                    .need(parent_need)
                    .need(parent_deletion_need)
                    .purge_self(fact.id),
                file.workspace_id,
                fact.id,
                file.created_at_ms,
            ));
        }
        let Some(author) = context_payload(context, &author_need, "file author")? else {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(file_deletion_need),
                Some(parent_need),
                Some(parent_deletion_need),
                Some(author_need),
            ]));
        };
        validate_author_user(author, file.workspace_id, file.author_user_id)?;
        let context_have = context_have_from_optional_needs(
            context,
            [
                Some(&signature_need),
                Some(&signer_need),
                Some(&file_deletion_need),
                Some(&parent_need),
                Some(&parent_deletion_need),
                Some(&author_need),
            ],
        );

        // 3. Materialize.
        Ok(share_fact_with_sync(
            output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(file_deletion_need),
                Some(parent_need),
                Some(parent_deletion_need),
                Some(author_need),
            ])
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "content_file",
                scope,
                file.file_id,
                file.file_id,
            ))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "sync_exact_fact",
                crate::protocol::auth::workspace::scope(file.workspace_id),
                fact.id,
                fact.id,
            ))
            .row_mutation(RowMutation::InsertValues(content_file_row(fact.id, &file))),
            file.workspace_id,
            fact,
            context_have,
        ))
    }
}

fn context_payload<'a>(
    context: &'a ProjectionContext,
    need: &crate::core::context::ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    project::context_payload(context, need, label)
}

fn output_with_needs(
    needs: impl IntoIterator<Item = Option<crate::core::context::ContextNeed>>,
) -> ProjectionOutput {
    needs
        .into_iter()
        .flatten()
        .fold(ProjectionOutput::new(), |output, need| output.need(need))
}

fn delete_file_projection(workspace_id: FactId, file_fact_id: FactId) -> ProjectionOutput {
    ProjectionOutput::new().row_mutation(RowMutation::DeleteWhere(content_file_delete(
        workspace_id,
        file_fact_id,
    )))
}

fn content_file_delete(workspace_id: FactId, file_fact_id: FactId) -> TableDeleteWhere {
    TableDeleteWhere {
        table: FILE_ROWS,
        columns: FILE_KEY_COLUMNS,
        values: vec![
            Value::Bytes(workspace_id.to_vec()),
            Value::Bytes(file_fact_id.to_vec()),
        ],
    }
}

fn parent_message_context<'a>(
    payload: &'a Fact,
    expected_scope: &FactScope,
    workspace_id: crate::core::facts::FactId,
    message_id: crate::core::facts::FactId,
    label: &str,
) -> Result<ParentMessageContext<'a>, String> {
    if payload.id != message_id {
        return Err("file parent context payload id mismatch".to_string());
    }
    if &payload.scope != expected_scope {
        return Err("file parent context scope does not match file workspace".to_string());
    }
    let parent = decode_parent_message_payload(payload, label)?;
    if parent.workspace_id != workspace_id {
        return Err("file parent message workspace does not match file".to_string());
    }
    Ok(ParentMessageContext {
        _payload: payload,
        message: parent,
    })
}

fn validate_author_user(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if payload.id != author_user_id {
        return Err("file author context payload id mismatch".to_string());
    }
    let author = crate::protocol::auth::user::decode_fact_payload(payload.body())
        .map_err(|_| "file author context is not an identity user".to_string())?;
    if author.workspace_id != workspace_id {
        return Err("file author workspace does not match file".to_string());
    }
    Ok(())
}

fn validate_file_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_file_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion = file_deletion::decode_fact_payload(payload.body())
        .map_err(|_| "file deletion context is not a content file deletion".to_string())?;
    if deletion.workspace_id != workspace_id {
        return Err("file deletion workspace does not match file".to_string());
    }
    if deletion.target_file_id != target_file_id {
        return Err("file deletion target does not match file".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("file deletion author does not match file author".to_string());
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
    let deletion = message_deletion::decode_fact_payload(payload.body())
        .map_err(|_| "parent deletion context is not a content message deletion".to_string())?;
    if deletion.workspace_id != workspace_id {
        return Err("parent deletion workspace does not match file".to_string());
    }
    if deletion.target_frontier_id != target_frontier_id {
        return Err("parent deletion frontier does not match file parent".to_string());
    }
    if deletion.target_minute != target_minute {
        return Err("parent deletion minute does not match file parent".to_string());
    }
    if deletion.target_message_id != target_message_id {
        return Err("parent deletion target does not match file parent".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("parent deletion author does not match parent message author".to_string());
    }
    Ok(())
}

struct ParentMessageContext<'a> {
    _payload: &'a Fact,
    message: ParentMessage,
}

struct ParentMessage {
    workspace_id: crate::core::facts::FactId,
    frontier_id: crate::core::facts::FactId,
    minute: u64,
    author_user_id: crate::core::facts::FactId,
}

fn decode_parent_message_payload(payload: &Fact, label: &str) -> Result<ParentMessage, String> {
    let message = project::decode_typed_fact(
        payload,
        message::TYPE_CONTENT_MESSAGE,
        label,
        message::decode_fact_payload,
    )
    .map_err(|_| format!("{label} context is not a content message"))?;
    Ok(ParentMessage {
        workspace_id: message.workspace_id,
        frontier_id: message.frontier_id,
        minute: message.minute,
        author_user_id: message.author_user_id,
    })
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content file fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::content::file::fact::{
        ContentFileFact, SealedMetadata, FILE_ROOT_HASH_BYTES,
    };
    use crate::protocol::content::file_slice::fact::FILE_SLICE_PLAINTEXT_BYTES;

    fn valid_file() -> ContentFileFact {
        ContentFileFact {
            workspace_id: [1; 32],
            created_at_ms: 100,
            message_id: [2; 32],
            author_user_id: [3; 32],
            signer_id: [4; 32],
            signer_public_key: [5; 32],
            file_id: [6; 32],
            blob_bytes: 1,
            total_slices: 1,
            slice_bytes: FILE_SLICE_PLAINTEXT_BYTES as u32,
            root_hash: [7; FILE_ROOT_HASH_BYTES],
            sealed_metadata: SealedMetadata::new(b"sealed").expect("metadata"),
        }
    }

    #[test]
    fn non_empty_files_use_the_fixed_slice_budget() {
        let mut file = valid_file();
        file.slice_bytes = 1_024;

        let err = super::authenticate::validate_file_fields(&file)
            .expect_err("reject non-standard slice budget");

        assert!(
            err.contains("fixed file-slice slot"),
            "unexpected error: {err}"
        );
    }
}
