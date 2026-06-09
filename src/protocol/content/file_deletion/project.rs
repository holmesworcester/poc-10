//! Poc-10 content-file-deletion projector.
//!
//! POLICY. A content_file_deletion is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped, signed, and contains a
//!      deletion payload for one target file and author user.
//!   2. AUTHORITY. The signer, target file, and author user contexts must all
//!      validate against the same workspace and target.
//!   3. MATERIALIZE. Once authorized, write the deletion row, publish the
//!      fact_purged offer, and share the deletion fact.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::{RowMutation, TableInsert, Value};
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};

use crate::protocol::auth::user;
use crate::protocol::auth::{endpoint_shared, signature};
use crate::protocol::content::file;
use crate::protocol::content::message::fact::unix_minute_for;
use crate::protocol::content::message::project::{self, FactSigner};
use crate::protocol::registry::read_models;
use crate::protocol::root;
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

/// Staged read pipeline for the file_deletion fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "content::file_deletion::Codec",
    authenticate: "content::file_deletion::authenticate::ContentFileDeletionAuthenticator",
    adapt: "content::file_deletion::adapt::ContentFileDeletionAdapter",
    project: "content::file_deletion::project::ContentFileDeletionProjector",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RootFileDeletionRefs {
    workspace_id: FactId,
    author_user_id: FactId,
    signer_id: FactId,
    target_file_id: FactId,
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
        project_staged::<
            super::Codec,
            super::authenticate::ContentFileDeletionAuthenticator,
            super::adapt::ContentFileDeletionAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<super::fact::ContentFileDeletionFact> for ContentFileDeletionProjector {
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
        let mut context_have = context_have;
        context_have.extend(root_ref_context_have_from_fact(fact));

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
            .offer(crate::core::pipeline::fact_purged_offer(
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

pub(crate) fn project_root_file_deletion(
    fact: &Fact,
    root_fact: &root::fact::RootFact,
    context: &ProjectionContext,
    root_context_output: ProjectionOutput,
) -> Result<ProjectionOutput, String> {
    if root_fact.family != super::ROOT_FAMILY_CONTENT_FILE_DELETION {
        return Err("root file deletion reader received wrong root family".to_string());
    }
    if root_fact.version != super::ROOT_VERSION_CONTENT_FILE_DELETION {
        return Err("unsupported content file deletion root version".to_string());
    }
    if root_fact.created_at_ms == 0 {
        return Err("content file deletion root created_at_ms cannot be zero".to_string());
    }

    let refs = root_file_deletion_refs(root_fact)?;
    let scope = crate::protocol::auth::workspace::scope(refs.workspace_id);
    if fact.scope != scope {
        return Err("content file deletion root scope does not match workspace ref".to_string());
    }

    let signer_need = project::signer_need(fact.id, refs.workspace_id, refs.signer_id);
    let target_need = crate::core::context::ContextNeed::range(
        fact.id,
        "sync_exact_fact",
        scope,
        refs.target_file_id,
        refs.target_file_id,
    );
    let author_need = crate::core::context::ContextNeed::range(
        fact.id,
        "auth_user",
        FactScope::Global,
        refs.author_user_id,
        refs.author_user_id,
    );
    let waiting = share_fact_with_sync(
        root_context_output
            .clone()
            .need(signer_need.clone())
            .need(target_need.clone())
            .need(author_need.clone()),
        refs.workspace_id,
        fact,
        root_ref_context_have(root_fact),
    );

    let Some(signer_fact) = context_payload(context, &signer_need, "file deletion signer")? else {
        return Ok(waiting);
    };
    let signer = endpoint_shared::decode_fact_payload(signer_fact.body())
        .map_err(|_| "file deletion signer context is not endpoint_shared".to_string())?;
    if signer.workspace_id != refs.workspace_id {
        return Err("file deletion signer workspace mismatch".to_string());
    }
    if signer.endpoint_id != refs.signer_id {
        return Err("file deletion signer endpoint mismatch".to_string());
    }
    if signer.user_authority_fact_id != refs.author_user_id {
        return Err("file deletion signer author mismatch".to_string());
    }

    let deletion = super::fact::ContentFileDeletionFact {
        workspace_id: refs.workspace_id,
        created_at_ms: root_fact.created_at_ms,
        target_file_id: refs.target_file_id,
        author_user_id: refs.author_user_id,
        signer_id: refs.signer_id,
        signer_public_key: signer.signing_public_key,
    };
    let output = ContentFileDeletionProjector::new().project_semantic(fact, deletion, context)?;
    Ok(project::merge_projection_outputs(
        output,
        root_context_output,
    ))
}

fn root_file_deletion_refs(
    root_fact: &root::fact::RootFact,
) -> Result<RootFileDeletionRefs, String> {
    for edge in &root_fact.refs {
        match edge.role {
            root::roles::WORKSPACE
            | root::roles::AUTHOR
            | root::roles::SIGNER
            | root::roles::TARGET => {}
            _ => return Err("content file deletion root contains unsupported ref role".to_string()),
        }
        if edge.index != 0 {
            return Err("content file deletion root contains unsupported ref index".to_string());
        }
    }
    let required = |role, label| {
        root_fact
            .ref_by_role_index(role, 0)
            .map(|edge| edge.target_fact_id)
            .ok_or_else(|| format!("content file deletion root missing {label} ref"))
    };
    Ok(RootFileDeletionRefs {
        workspace_id: required(root::roles::WORKSPACE, "workspace")?,
        author_user_id: required(root::roles::AUTHOR, "author")?,
        signer_id: required(root::roles::SIGNER, "signer")?,
        target_file_id: required(root::roles::TARGET, "target")?,
    })
}

fn root_ref_context_have(root_fact: &root::fact::RootFact) -> Vec<FactId> {
    root_fact
        .refs
        .iter()
        .map(|edge| edge.target_fact_id)
        .collect()
}

fn root_ref_context_have_from_fact(fact: &Fact) -> Vec<FactId> {
    root::decode_fact_payload(fact.body())
        .map(|root_fact| root_ref_context_have(&root_fact))
        .unwrap_or_default()
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
) -> Result<project::MessageContext, String> {
    if parent_fact.id != target.message_id {
        return Err("file deletion parent context payload id mismatch".to_string());
    }
    if &parent_fact.scope != expected_scope {
        return Err("file deletion parent scope does not match deletion".to_string());
    }
    let parent = project::message_context_from_fact(parent_fact, "file deletion parent")
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

    use crate::core::crypto;
    use crate::core::pipeline::{MatchedContext, ProjectionContext, Projector};
    use crate::protocol::auth;
    use crate::protocol::auth::endpoint_shared::{
        encode as endpoint_shared_layout,
        fact::{EndpointRole, EndpointSharedFact},
    };
    use crate::protocol::auth::user::{encode as user_layout, fact::UserFact};
    use crate::protocol::content::file::encode as file_encode;
    use crate::protocol::content::file_deletion::FILE_DELETION_ROWS;
    use crate::protocol::content::message::{
        encode as message_encode,
        fact::{ContentMessageFact, MessageCiphertext},
    };
    use crate::protocol::root;

    const FILE_DELETION_COLUMNS: &[&str] = read_models::FILE_DELETIONS.columns;
    const CONTENT_SIGNING_KEY: [u8; 32] = [7; 32];
    const ENDPOINT_AUTHORITY_KEY: [u8; 32] = [13; 32];
    const CONTENT_SIGNER_ID: FactId = [8; 32];

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

    #[test]
    fn root_file_deletion_materializes_authorized_author_delete() {
        let workspace_id = [9; 32];
        let author = user_fact(workspace_id, [22; 32], "alice");
        let message = message_fact(workspace_id, author.id);
        let file = file_fact(workspace_id, message.id, author.id);
        let deletion = root_deletion_fact(workspace_id, file.id, author.id);
        let signer = signer_fact(workspace_id, author.id);

        let output = root::project::RootProjector::new()
            .project(
                &deletion,
                &ProjectionContext::from_matches(vec![
                    signature_match(&deletion, workspace_id),
                    signer_match(&deletion, workspace_id, &signer),
                    target_match(&deletion, workspace_id, &file),
                    parent_match(&deletion, workspace_id, &message),
                    author_match(&deletion, &author),
                ]),
            )
            .expect("project root file deletion");

        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role == root::project::ROOT_ENVELOPE_ROLE));
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role == "fact_purged"));
        let RowMutation::InsertValues(stored) = output
            .effects
            .row_mutations
            .iter()
            .find(|mutation| matches!(mutation, RowMutation::InsertValues(row) if row.table == FILE_DELETION_ROWS))
            .expect("deletion row")
        else {
            panic!("expected insert values mutation");
        };
        assert_eq!(
            stored.values[1],
            crate::core::intents::Value::Bytes(file.id.to_vec())
        );
        assert_eq!(
            stored.values[2],
            crate::core::intents::Value::Bytes(deletion.id.to_vec())
        );
        assert_eq!(output.effects.intents.len(), 1);
        let share = crate::protocol::sync::share_fact_with_sync::decode_share_fact_with_sync(
            &output.effects.intents[0],
        )
        .expect("decode sync share");
        assert!(share.context_have.contains(&file.id));
        assert!(share.context_have.contains(&author.id));
        assert!(share.context_have.contains(&CONTENT_SIGNER_ID));
    }

    fn root_deletion_fact(
        workspace_id: FactId,
        target_file_id: FactId,
        author_user_id: FactId,
    ) -> Fact {
        let root = root::fact::RootFact {
            family: crate::protocol::content::file_deletion::ROOT_FAMILY_CONTENT_FILE_DELETION,
            version: crate::protocol::content::file_deletion::ROOT_VERSION_CONTENT_FILE_DELETION,
            created_at_ms: 12_345,
            refs: vec![
                root::fact::RootRef::new(root::roles::WORKSPACE, 0, workspace_id)
                    .expect("workspace ref"),
                root::fact::RootRef::new(root::roles::AUTHOR, 0, author_user_id)
                    .expect("author ref"),
                root::fact::RootRef::new(root::roles::SIGNER, 0, CONTENT_SIGNER_ID)
                    .expect("signer ref"),
                root::fact::RootRef::new(root::roles::TARGET, 0, target_file_id)
                    .expect("target ref"),
            ],
        };
        Fact::new(
            crate::protocol::auth::workspace::scope(workspace_id),
            root.created_at_ms,
            root::encode::encode_fact(&root).expect("encode root deletion"),
        )
    }

    fn message_fact(workspace_id: FactId, author_user_id: FactId) -> Fact {
        let message = ContentMessageFact {
            workspace_id,
            author_user_id,
            created_at_ms: 12_000,
            signer_id: CONTENT_SIGNER_ID,
            signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
            frontier_id: [3; 32],
            local_history_node_secret_id: [0; 32],
            expires_at_minute: u64::MAX,
            retention_policy_id: [0; 32],
            minute: 12,
            nonce: [5; crate::protocol::content::message::fact::NONCE_BYTES],
            ciphertext: MessageCiphertext::new(&vec![
                6;
                crate::protocol::content::message::fact::CIPHERTEXT_BYTES
            ])
            .expect("message ciphertext"),
        };
        Fact::new(
            crate::protocol::auth::workspace::scope(workspace_id),
            message.created_at_ms,
            message_encode::encode_fact(&message).expect("encode message"),
        )
    }

    fn file_fact(workspace_id: FactId, message_id: FactId, author_user_id: FactId) -> Fact {
        let file = file::fact::ContentFileFact {
            workspace_id,
            created_at_ms: 12_100,
            message_id,
            author_user_id,
            signer_id: CONTENT_SIGNER_ID,
            signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
            file_id: [55; 32],
            blob_bytes: 128,
            total_slices: 1,
            slice_bytes: 128,
            root_hash: [77; 32],
            sealed_metadata: file::fact::SealedMetadata::new(b"sealed metadata").expect("metadata"),
        };
        Fact::new(
            crate::protocol::auth::workspace::scope(workspace_id),
            file.created_at_ms,
            file_encode::encode_fact(&file).expect("encode file"),
        )
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

    fn signature_match(deletion: &Fact, workspace_id: FactId) -> MatchedContext {
        let signature = auth::signature::author::create_signature(
            workspace_id,
            deletion.id,
            &CONTENT_SIGNING_KEY,
            deletion.timestamp,
        )
        .expect("signature evidence");
        let signer_public_key = crypto::ed25519_public_key(&CONTENT_SIGNING_KEY);
        let scope = crate::protocol::auth::workspace::scope(workspace_id);
        MatchedContext {
            need: auth::signature::project::signature_proof_need(
                deletion.id,
                scope.clone(),
                deletion.id,
                signer_public_key,
            )
            .expect("signature need"),
            offer: auth::signature::project::signature_proof_offer(
                signature.id,
                scope,
                deletion.id,
                signer_public_key,
            )
            .expect("signature offer"),
            payload: signature,
        }
    }

    fn signer_match(deletion: &Fact, workspace_id: FactId, signer: &Fact) -> MatchedContext {
        let scope = crate::protocol::auth::workspace::scope(workspace_id);
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                deletion.id,
                "content_signer",
                scope.clone(),
                CONTENT_SIGNER_ID,
                CONTENT_SIGNER_ID,
            ),
            offer: crate::core::context::ContextOffer::range(
                signer.id,
                "content_signer",
                scope,
                CONTENT_SIGNER_ID,
                CONTENT_SIGNER_ID,
            ),
            payload: signer.clone(),
        }
    }

    fn target_match(deletion: &Fact, workspace_id: FactId, file: &Fact) -> MatchedContext {
        let scope = crate::protocol::auth::workspace::scope(workspace_id);
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                deletion.id,
                "sync_exact_fact",
                scope.clone(),
                file.id,
                file.id,
            ),
            offer: crate::core::context::ContextOffer::range(
                file.id,
                "sync_exact_fact",
                scope,
                file.id,
                file.id,
            ),
            payload: file.clone(),
        }
    }

    fn parent_match(deletion: &Fact, workspace_id: FactId, message: &Fact) -> MatchedContext {
        let scope = crate::protocol::auth::workspace::scope(workspace_id);
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                deletion.id,
                "content_message",
                scope.clone(),
                message.id,
                message.id,
            ),
            offer: crate::core::context::ContextOffer::range(
                message.id,
                "content_message",
                scope,
                message.id,
                message.id,
            ),
            payload: message.clone(),
        }
    }

    fn author_match(deletion: &Fact, author: &Fact) -> MatchedContext {
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                deletion.id,
                "auth_user",
                FactScope::Global,
                author.id,
                author.id,
            ),
            offer: crate::core::context::ContextOffer::range(
                author.id,
                "auth_user",
                FactScope::Global,
                author.id,
                author.id,
            ),
            payload: author.clone(),
        }
    }
}
