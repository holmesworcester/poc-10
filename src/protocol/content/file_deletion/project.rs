pub mod decode {
    //! Byte decoding for content-file-deletion target facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{CONTENT_FILE_DELETION_BYTES, TYPE_CONTENT_FILE_DELETION};
    use super::super::fact::ContentFileDeletionFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<ContentFileDeletionFact, String> {
        let mut reader = wire::Reader::new(bytes);
        reader
            .expect_len(CONTENT_FILE_DELETION_BYTES)
            .map_err(wire_err)?;
        let tag = reader.u8().map_err(wire_err)?;
        if tag != TYPE_CONTENT_FILE_DELETION {
            return Err("expected content file deletion fact".to_string());
        }
        let fact = ContentFileDeletionFact {
            workspace_id: reader.array().map_err(wire_err)?,
            created_at_ms: reader.u64be().map_err(wire_err)?,
            target_file_id: reader.array().map_err(wire_err)?,
            author_user_id: reader.array().map_err(wire_err)?,
            signer_id: reader.array().map_err(wire_err)?,
            signer_public_key: reader.array().map_err(wire_err)?,
        };
        reader.finish().map_err(wire_err)?;
        Ok(fact)
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::content::file_deletion::encode::{
            encode_fact, CONTENT_FILE_DELETION_BYTES, TYPE_CONTENT_FILE_DELETION,
        };

        fn fact() -> ContentFileDeletionFact {
            ContentFileDeletionFact {
                workspace_id: [1; 32],
                created_at_ms: 9_000,
                target_file_id: [2; 32],
                author_user_id: [3; 32],
                signer_id: [9; 32],
                signer_public_key: [10; 32],
            }
        }

        #[test]
        fn content_file_deletion_roundtrips_fixed_width() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), CONTENT_FILE_DELETION_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[0] = TYPE_CONTENT_FILE_DELETION.wrapping_add(1);
            assert!(decode_fact(&encoded).is_err());
        }
    }
}
pub mod authenticate {
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
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::ContentFileDeletionFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        deletion: ContentFileDeletionFact,
        _context: &ProjectionContext,
    ) -> Result<ContentFileDeletionFact, String> {
        prove_decoded_file_deletion(fact, deletion)
    }

    fn prove_decoded_file_deletion(
        fact: &Fact,
        deletion: ContentFileDeletionFact,
    ) -> Result<ContentFileDeletionFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(deletion)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::command::LocalSigningCapability;
        use crate::core::crypto;
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::content::file_deletion::author::delete_file;
        use crate::protocol::content::file_deletion::fact::ContentFileDeletionFact;

        const PRIVATE_KEY: [u8; 32] = [7; 32];
        const WORKSPACE_ID: [u8; 32] = [1; 32];

        fn signing_capability() -> LocalSigningCapability {
            LocalSigningCapability {
                workspace_id: WORKSPACE_ID,
                signer_id: [2; 32],
                public_key: crypto::ed25519_public_key(&PRIVATE_KEY),
                private_key: PRIVATE_KEY,
            }
        }

        fn canonical_fact() -> Fact {
            delete_file(&signing_capability(), WORKSPACE_ID, 100, [3; 32], [4; 32])
                .expect("content file deletion fact")
        }

        fn authenticate(fact: &Fact) -> Result<ContentFileDeletionFact, String> {
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
    //! Content-file-deletion semantic adapter.
    //!
    //! The current file_deletion wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::ContentFileDeletionFact;

    pub(crate) fn adapt(
        source: ContentFileDeletionFact,
    ) -> Result<ContentFileDeletionFact, String> {
        Ok(source)
    }
}

// Poc-10 content-file-deletion projector.
//
// POLICY. A content_file_deletion is admitted iff:
//   1. STRUCTURAL. The fact is workspace-scoped, signed, and contains a
//      deletion payload for one target file and author user.
//   2. AUTHORITY. The signer, target file, and author user contexts must all
//      validate against the same workspace and target.
//   3. MATERIALIZE. Once authorized, write the deletion row, publish the
//      fact_purged offer, and share the deletion fact.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{RowMutation, TableInsert, Value};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};

use crate::protocol::auth::signature;
use crate::protocol::auth::user;
use crate::protocol::content::message::fact::unix_minute_for;
use crate::protocol::content::message::project::{self, FactSigner};
use crate::protocol::content::{file, message};
use crate::protocol::registry::read_models;
use crate::protocol::sync::shared_fact::project::{
    context_have_from_optional_needs, share_fact_with_sync,
};

use super::queries::FileDeletionRow;

fn file_deletion_row(input: FileDeletionRow) -> TableInsert {
    read_models::FILE_DELETIONS.insert(vec![
        Value::Bytes(input.workspace_id.to_vec()),
        Value::Bytes(input.target_file_id.to_vec()),
        Value::Bytes(input.deletion_id.to_vec()),
        Value::U64(input.created_at_ms),
        Value::Bytes(input.author_user_id.to_vec()),
    ])
}

/// Projector route metadata for the file_deletion fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("content::file_deletion::project::ContentFileDeletionProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct ContentFileDeletionProjector;

impl ContentFileDeletionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentFileDeletionProjector {
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

impl ContentFileDeletionProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        deletion: super::fact::ContentFileDeletionFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(deletion.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Authority and signature evidence.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            scope.clone(),
            fact.id,
            deletion.signer_public_key,
        )?;
        let signer_need = project::signer_need(fact.id, deletion.workspace_id, deletion.signer_id);
        let target_need = crate::core::context::ContextNeed::range(
            fact.id,
            "sync_exact_fact",
            scope.clone(),
            deletion.target_file_id,
            deletion.target_file_id,
        );
        let author_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_user",
            crate::core::facts::FactScope::Global,
            deletion.author_user_id,
            deletion.author_user_id,
        );
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            deletion.workspace_id,
            fact.id,
            deletion.signer_public_key,
            "file deletion",
        )? {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(author_need),
            ]));
        }
        if !project::validate_signer_context(
            context,
            &signer_need,
            FactSigner {
                signer_id: deletion.signer_id,
                signer_public_key: deletion.signer_public_key,
            },
            deletion.workspace_id,
            Some(deletion.author_user_id),
            "file deletion",
        )? {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(author_need),
            ]));
        }
        let Some(target_fact) = context_payload(context, &target_need, "file deletion target")?
        else {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(author_need),
            ]));
        };
        let target = validate_target_file(&deletion, target_fact, &scope)?;
        let parent_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_message",
            scope.clone(),
            target.message_id,
            target.message_id,
        );
        let Some(parent_fact) =
            context_payload(context, &parent_need, "file deletion parent message")?
        else {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(parent_need),
                Some(author_need),
            ]));
        };
        let parent = validate_parent_message(&target, parent_fact, &scope)?;
        let Some(author_fact) = context_payload(context, &author_need, "file deletion author")?
        else {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(parent_need),
                Some(author_need),
            ]));
        };
        validate_author_user(&deletion, author_fact)?;
        let context_have = context_have_from_optional_needs(
            context,
            [
                Some(&signature_need),
                Some(&signer_need),
                Some(&target_need),
                Some(&parent_need),
                Some(&author_need),
            ],
        );

        // 3. Materialize.
        let row = file_deletion_row(FileDeletionRow {
            workspace_id: deletion.workspace_id,
            target_file_id: deletion.target_file_id,
            deletion_id: fact.id,
            created_at_ms: deletion.created_at_ms,
            author_user_id: deletion.author_user_id,
        });
        Ok(share_fact_with_sync(
            output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(parent_need),
                Some(author_need),
            ])
            .offer(crate::core::project_fact::fact_purged_offer(
                fact.id,
                scope,
                project::fact_purged_key(
                    parent.frontier_id,
                    unix_minute_for(target.created_at_ms),
                    deletion.target_file_id,
                ),
            ))
            .row_mutation(RowMutation::InsertValues(row)),
            deletion.workspace_id,
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

fn validate_target_file(
    deletion: &super::fact::ContentFileDeletionFact,
    target_fact: &Fact,
    expected_scope: &FactScope,
) -> Result<file::fact::ContentFileFact, String> {
    if target_fact.id != deletion.target_file_id {
        return Err("file deletion target context payload id mismatch".to_string());
    }
    if &target_fact.scope != expected_scope {
        return Err("file deletion target scope does not match deletion".to_string());
    }
    let target = project::decode_typed_fact(
        target_fact,
        file::TYPE_CONTENT_FILE,
        "file deletion target",
        file::decode_fact_payload,
    )
    .map_err(|_| "file deletion target context must be a content file".to_string())?;
    if target.workspace_id != deletion.workspace_id {
        return Err("file deletion target workspace does not match deletion".to_string());
    }
    if target.author_user_id != deletion.author_user_id {
        return Err("file deletion author is not the target file author".to_string());
    }
    Ok(target)
}

fn validate_parent_message(
    target: &file::fact::ContentFileFact,
    parent_fact: &Fact,
    expected_scope: &FactScope,
) -> Result<message::fact::ContentMessageFact, String> {
    if parent_fact.id != target.message_id {
        return Err("file deletion parent context payload id mismatch".to_string());
    }
    if &parent_fact.scope != expected_scope {
        return Err("file deletion parent scope does not match deletion".to_string());
    }
    let parent = project::decode_typed_fact(
        parent_fact,
        message::TYPE_CONTENT_MESSAGE,
        "file deletion parent",
        message::decode_fact_payload,
    )
    .map_err(|_| "file deletion parent context must be a content message".to_string())?;
    if parent.workspace_id != target.workspace_id {
        return Err("file deletion parent workspace does not match file".to_string());
    }
    Ok(parent)
}

fn validate_author_user(
    deletion: &super::fact::ContentFileDeletionFact,
    author_fact: &Fact,
) -> Result<(), String> {
    if author_fact.id != deletion.author_user_id {
        return Err("file deletion author context payload id mismatch".to_string());
    }
    let author = user::decode_fact_payload(author_fact.body())
        .map_err(|_| "file deletion author context must be an identity user".to_string())?;
    if author.workspace_id != deletion.workspace_id {
        return Err("file deletion author workspace does not match deletion".to_string());
    }
    Ok(())
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content file deletion fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::protocol::content::file_deletion::FILE_DELETION_ROWS;

    const FILE_DELETION_COLUMNS: &[&str] = read_models::FILE_DELETIONS.columns;

    #[test]
    fn file_deletion_row_round_trips() {
        let input = FileDeletionRow {
            workspace_id: [1; 32],
            target_file_id: [2; 32],
            deletion_id: [3; 32],
            created_at_ms: 4_242,
            author_user_id: [4; 32],
        };
        let row = file_deletion_row(input);
        assert_eq!(row.table, FILE_DELETION_ROWS);
        assert_eq!(row.columns, FILE_DELETION_COLUMNS);
        assert_eq!(row.values[0], Value::Bytes(vec![1; 32]));
        assert_eq!(row.values[1], Value::Bytes(vec![2; 32]));
        assert_eq!(row.values[2], Value::Bytes(vec![3; 32]));
        assert_eq!(row.values[3], Value::U64(4_242));
        assert_eq!(row.values[4], Value::Bytes(vec![4; 32]));
    }
}
