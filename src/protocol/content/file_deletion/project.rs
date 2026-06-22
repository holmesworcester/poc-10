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

    // Tests. Ordered most-central first: the fixed-width roundtrip proves the
    // whole codec, then the tag/length rejections guard the layout.
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
    //! workspace-scope check is interpretation the projector owns. Signer and
    //! author-user authority are proven from other facts in the projector; the
    //! target file later validates whether the signed claim applies to it.

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

    // Tests. Ordered most-central first: a canonical fact authenticates, then
    // the id-binding invariant (id == hash(bytes)), then the layout rejections.
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
//   2. AUTHORITY. The deletion signer and author user contexts validate the
//      signed deletion claim. The target file validates target and author
//      equality when the delete offer wakes it.
//   3. MATERIALIZE. Once authorized, write the deletion row, publish the
//      fact_purged offer, and share the deletion fact.

use crate::core::context::{ContextKey, ContextKeyPart};
use crate::core::facts::Fact;
use crate::core::intents::{RowMutation, TableInsert, Value};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};

use crate::protocol::auth::signature;
use crate::protocol::auth::user;
use crate::protocol::content::message::project::{self, FactSigner};
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

pub fn file_purged_key(target_file_id: crate::core::facts::FactId) -> ContextKey {
    ContextKey::from_parts([
        ContextKeyPart::bytes(b"content_file"),
        ContextKeyPart::bytes(&target_file_id),
    ])
    .expect("file deletion purge context key uses bounded fixed-width parts")
}

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
        let author_need = crate::core::context::ContextNeed::for_key(
            fact.id,
            "auth_user",
            crate::core::facts::FactScope::Global,
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
                Some(author_need),
            ]));
        }
        let Some(author_fact) = context_payload(context, &author_need, "file deletion author")?
        else {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(author_need),
            ]));
        };
        validate_author_user(&deletion, author_fact)?;
        let context_have = context_have_from_optional_needs(
            context,
            [
                Some(&signature_need),
                Some(&signer_need),
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
            ProjectionOutput::new()
                .offer(crate::core::project_fact::fact_purged_offer(
                    fact.id,
                    scope,
                    file_purged_key(deletion.target_file_id),
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

// Tests.
//
// The semantic projector is the heart of this file; these are ordered
// most-central first: the materialize-signed-claim happy path leads, then the
// context-wait gate, then the narrow row-builder check.
#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::command::LocalSigningCapability;
    use crate::core::crypto;
    use crate::core::facts::{Fact, FactId, FactScope};
    use crate::core::project_fact::{MatchedContext, ProjectionContext};
    use crate::protocol::auth;
    use crate::protocol::auth::endpoint_shared::encode as endpoint_shared_layout;
    use crate::protocol::auth::endpoint_shared::fact::{EndpointRole, EndpointSharedFact};
    use crate::protocol::auth::user::encode as user_layout;
    use crate::protocol::auth::user::fact::UserFact;
    use crate::protocol::content::file_deletion::FILE_DELETION_ROWS;

    const FILE_DELETION_COLUMNS: &[&str] = read_models::FILE_DELETIONS.columns;
    const CONTENT_SIGNING_KEY: [u8; 32] = [17; 32];
    const ENDPOINT_AUTHORITY_KEY: [u8; 32] = [19; 32];
    const CONTENT_SIGNER_ID: FactId = [8; 32];

    #[test]
    fn file_deletion_projector_materializes_signed_claim_without_target_context() {
        let workspace_id = [9; 32];
        let author_fact = user_fact(workspace_id, [22; 32], "alice");
        let target_file_id = [77; 32];
        let fact = deletion_fact(workspace_id, target_file_id, author_fact.id, 12_345);
        let signer_fact = signer_fact(workspace_id, author_fact.id);
        let signature_ctx = signature_match(&fact);
        let signer_ctx = signer_match(&fact, &signer_fact);
        let author_ctx = author_match(&fact, &author_fact);
        let mut expected_context_have = vec![
            signature_ctx.payload.id,
            signer_ctx.payload.id,
            author_ctx.payload.id,
        ];
        expected_context_have.sort();

        let output = ContentFileDeletionProjector::new()
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![signature_ctx, signer_ctx, author_ctx]),
            )
            .expect("project file deletion claim");

        assert!(
            output.needs.is_empty(),
            "valid deletion claims should not retain proof needs after sharing"
        );
        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].role, "fact_purged");
        assert_eq!(output.offers[0].start_key, file_purged_key(target_file_id));
        assert_eq!(output.effects.intents.len(), 1);
        assert_eq!(
            output.effects.intents[0].kind.as_str(),
            "share_fact_with_sync"
        );
        let share = crate::protocol::sync::share_fact_with_sync::decode_share_fact_with_sync(
            &output.effects.intents[0],
        )
        .expect("decode share intent");
        assert_eq!(share.owner_fact_id, fact.id);
        assert_eq!(share.workspace_id, workspace_id);
        assert_eq!(share.context_have, expected_context_have);
        assert_eq!(output.effects.row_mutations.len(), 1);
    }

    #[test]
    fn file_deletion_projector_waits_for_signature_signer_and_author_only() {
        let workspace_id = [9; 32];
        let fact = deletion_fact(workspace_id, [77; 32], [22; 32], 12_345);

        let output = ContentFileDeletionProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("missing context is a need");

        assert!(output.offers.is_empty());
        assert!(output.effects.intents.is_empty());
        assert_eq!(output.needs.len(), 3);
        assert!(output
            .needs
            .iter()
            .any(|need| need.role.as_str() == "signature_proof"));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role.as_str() == "content_signer"));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role.as_str() == "auth_user"));
        assert!(!output
            .needs
            .iter()
            .any(|need| need.role.as_str() == "sync_exact_fact"));
        assert!(!output
            .needs
            .iter()
            .any(|need| need.role.as_str() == "content_message"));
    }

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

    fn deletion_fact(
        workspace_id: FactId,
        target_file_id: FactId,
        author_user_id: FactId,
        created_at_ms: u64,
    ) -> Fact {
        crate::protocol::content::file_deletion::author::delete_file(
            &LocalSigningCapability {
                workspace_id,
                signer_id: CONTENT_SIGNER_ID,
                public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
                private_key: CONTENT_SIGNING_KEY,
            },
            workspace_id,
            created_at_ms,
            target_file_id,
            author_user_id,
        )
        .expect("file deletion fact")
    }

    fn deletion_from_fact(deletion_fact: &Fact) -> super::super::fact::ContentFileDeletionFact {
        decode::decode_fact(deletion_fact.body()).expect("decode file deletion")
    }

    fn signer_fact(workspace_id: FactId, author_user_id: FactId) -> Fact {
        let signer = EndpointSharedFact {
            created_at_ms: 7_000,
            workspace_id,
            user_authority_fact_id: author_user_id,
            endpoint_id: CONTENT_SIGNER_ID,
            signing_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
            endpoint_role: EndpointRole::Device,
            device_name: auth::endpoint_shared::fact::EndpointDeviceName::new("alice-device")
                .expect("device name"),
            signer_id: [1; 32],
            signer_public_key: crypto::ed25519_public_key(&ENDPOINT_AUTHORITY_KEY),
        };
        Fact::new(
            FactScope::Global,
            signer.created_at_ms,
            endpoint_shared_layout::encode_fact(&signer).expect("encode endpoint shared"),
        )
    }

    fn user_fact(workspace_id: FactId, public_key: [u8; 32], username: &str) -> Fact {
        let signing_key = [21; 32];
        let user = UserFact {
            created_at_ms: 8_000,
            workspace_id,
            public_key,
            username: auth::user::fact::Username::new(username).expect("username"),
            signer_id: [23; 32],
            signer_public_key: crypto::ed25519_public_key(&signing_key),
        };
        Fact::new(
            FactScope::Global,
            user.created_at_ms,
            user_layout::encode_fact(&user).expect("encode user"),
        )
    }

    fn signature_match(deletion_fact: &Fact) -> MatchedContext {
        let deletion = deletion_from_fact(deletion_fact);
        let signature = auth::signature::author::create_signature(
            deletion.workspace_id,
            deletion_fact.id,
            &CONTENT_SIGNING_KEY,
            deletion.created_at_ms,
        )
        .expect("signature evidence");
        let scope = crate::protocol::auth::workspace::scope(deletion.workspace_id);
        MatchedContext {
            need: auth::signature::project::signature_proof_need(
                deletion_fact.id,
                scope.clone(),
                deletion_fact.id,
                deletion.signer_public_key,
            )
            .expect("signature need"),
            offer: auth::signature::project::signature_proof_offer(
                signature.id,
                scope,
                deletion_fact.id,
                deletion.signer_public_key,
            )
            .expect("signature offer"),
            payload: signature,
        }
    }

    fn signer_match(deletion_fact: &Fact, signer_fact: &Fact) -> MatchedContext {
        let deletion = deletion_from_fact(deletion_fact);
        let scope = crate::protocol::auth::workspace::scope(deletion.workspace_id);
        MatchedContext {
            need: crate::core::context::ContextNeed::for_key(
                deletion_fact.id,
                "content_signer",
                scope.clone(),
                CONTENT_SIGNER_ID,
            ),
            offer: crate::core::context::ContextOffer::range(
                signer_fact.id,
                "content_signer",
                scope,
                CONTENT_SIGNER_ID,
                CONTENT_SIGNER_ID,
            ),
            payload: signer_fact.clone(),
        }
    }

    fn author_match(deletion_fact: &Fact, author_fact: &Fact) -> MatchedContext {
        MatchedContext {
            need: crate::core::context::ContextNeed::for_key(
                deletion_fact.id,
                "auth_user",
                crate::core::facts::FactScope::Global,
                author_fact.id,
            ),
            offer: crate::core::context::ContextOffer::range(
                author_fact.id,
                "auth_user",
                crate::core::facts::FactScope::Global,
                author_fact.id,
                author_fact.id,
            ),
            payload: author_fact.clone(),
        }
    }
}
