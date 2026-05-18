//! Content-file projector.
//!
//! POLICY. A content_file is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped, has valid descriptor fields,
//!      and contains a raw or signed content_file payload.
//!   2. CONTEXT. Projection waits for signer, parent sealed message, deletion,
//!      and author context; deletion context removes the descriptor row.
//!   3. MATERIALIZE. Live files publish file/exact-fact offers, write the
//!      descriptor row, and share the fact. File bytes remain slice facts.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::facts::content::file_deletion;
use crate::protocol::facts::content::message::authority::{self, DecodedPayload};
use crate::protocol::facts::content::sealed_message;
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::user;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;
use crate::protocol::matchers as message_matchers;

use super::fact::MAX_FILE_BYTES;
use super::rows::{content_file_key, content_file_row, FILE_ROWS};

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
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ContentFileProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        decoded: authority::DecodedFact<super::fact::ContentFileFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let file = decoded.payload;
        validate_file_fields(&file)?;
        let scope = message_matchers::workspace_scope(file.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Context and deletion gates.
        let signer_need = authority::signer_need(fact.id, decoded.signer);
        let file_deletion_need =
            message_matchers::deletion_need(fact.id, scope.clone(), fact.id, file.author_user_id);
        let parent_need = message_matchers::message_need(fact.id, scope.clone(), file.message_id);
        let author_need = crate::protocol::matchers::exact_need(
            fact.id,
            crate::protocol::matchers::user_role(),
            file.author_user_id,
        );
        if let (Some(signer), Some(need)) = (decoded.signer, signer_need.as_ref()) {
            if !authority::validate_signer_context(
                context,
                need,
                signer,
                file.workspace_id,
                Some(file.author_user_id),
                "file",
            )? {
                return Ok(output_with_needs([
                    signer_need,
                    Some(parent_need),
                    Some(file_deletion_need),
                    Some(author_need),
                    None,
                ]));
            }
        }
        if let Some(deletion) = context_payload(context, &file_deletion_need, "file deletion")? {
            validate_file_deletion(deletion, file.workspace_id, fact.id, file.author_user_id)?;
            return Ok(delete_file_projection(file.workspace_id, fact.id).need(file_deletion_need));
        }
        let Some(parent_payload) = context_payload(context, &parent_need, "file parent")? else {
            return Ok(output_with_needs([
                signer_need,
                Some(parent_need),
                Some(file_deletion_need),
                Some(author_need),
                None,
            ]));
        };
        let parent = parent_message_context(
            parent_payload,
            &scope,
            file.workspace_id,
            file.message_id,
            "file parent",
        )?;
        let parent_deletion_need = message_matchers::deletion_need(
            fact.id,
            scope.clone(),
            file.message_id,
            parent.message.author_user_id,
        );
        if let Some(deletion) =
            context_payload(context, &parent_deletion_need, "file parent deletion")?
        {
            validate_message_deletion(
                deletion,
                file.workspace_id,
                file.message_id,
                parent.message.author_user_id,
            )?;
            return Ok(delete_file_projection(file.workspace_id, fact.id)
                .need(file_deletion_need)
                .need(parent_need)
                .need(parent_deletion_need));
        }
        let Some(author) = context_payload(context, &author_need, "file author")? else {
            return Ok(output_with_needs([
                signer_need,
                Some(file_deletion_need),
                Some(parent_need),
                Some(parent_deletion_need),
                Some(author_need),
            ]));
        };
        validate_author_user(author, file.workspace_id, file.author_user_id)?;

        // 3. Materialize.
        Ok(output_with_needs([
            signer_need,
            Some(file_deletion_need),
            Some(parent_need),
            Some(parent_deletion_need),
            Some(author_need),
        ])
        .offer(matchers::file_offer(fact.id, scope, file.file_id))
        .offer(crate::protocol::matchers::exact_fact_offer(
            fact.id,
            message_matchers::workspace_scope(file.workspace_id),
            fact.id,
            fact.id,
        ))
        .intent(AtomicIntent::PutRow(content_file_row(fact.id, &file)?).into_intent())
        .intent(share_fact_with_workspace_intent_for_fact(
            file.workspace_id,
            fact,
        )))
    }
}

fn context_payload<'a>(
    context: &'a ProjectionContext,
    need: &crate::core::context::ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    authority::context_payload(context, need, label)
}

fn output_with_needs(
    needs: impl IntoIterator<Item = Option<crate::core::context::ContextNeed>>,
) -> ProjectionOutput {
    needs
        .into_iter()
        .flatten()
        .fold(ProjectionOutput::new(), |output, need| output.need(need))
}

fn delete_file_projection(
    workspace_id: crate::core::facts::FactId,
    file_fact_id: crate::core::facts::FactId,
) -> ProjectionOutput {
    ProjectionOutput::new().intent(
        AtomicIntent::DeleteRow(TableDelete {
            table: FILE_ROWS,
            key: content_file_key(&workspace_id, &file_fact_id),
        })
        .into_intent(),
    )
}

fn validate_file_fields(file: &super::fact::ContentFileFact) -> Result<(), String> {
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
    let author_payload = maybe_signed_payload(payload, user::TYPE_USER, "file author")?;
    let author =
        crate::protocol::facts::identity::user::decode_fact_payload(&author_payload.payload)
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
    let deletion_payload = maybe_signed_payload(
        payload,
        file_deletion::TYPE_CONTENT_FILE_DELETION,
        "file deletion",
    )?;
    let deletion = file_deletion::decode_fact_payload(&deletion_payload.payload)
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
    target_message_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion_payload = maybe_signed_payload(
        payload,
        sealed_message::TYPE_MESSAGE_DELETION,
        "parent deletion",
    )?;
    let deletion = sealed_message::decode_message_deletion_payload(&deletion_payload.payload)
        .map_err(|_| "parent deletion context is not a sealed message deletion".to_string())?;
    if deletion.workspace_id != workspace_id {
        return Err("parent deletion workspace does not match file".to_string());
    }
    if deletion.target_id != target_message_id {
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
    author_user_id: crate::core::facts::FactId,
}

fn decode_parent_message_payload(payload: &Fact, label: &str) -> Result<ParentMessage, String> {
    let sealed_payload = maybe_signed_payload(payload, sealed_message::TYPE_SEALED_MESSAGE, label)?;
    let sealed = sealed_message::decode_sealed_message_payload(&sealed_payload.payload)
        .map_err(|_| format!("{label} context is not a sealed message"))?;
    Ok(ParentMessage {
        workspace_id: sealed.workspace_id,
        author_user_id: sealed.author_user_id,
    })
}

fn maybe_signed_payload(
    payload: &Fact,
    expected_type: u8,
    label: &str,
) -> Result<DecodedPayload, String> {
    if payload.bytes.first().copied() == Some(identity::signed_fact::TYPE_SIGNED_FACT) {
        authority::decode_raw_or_signed(payload, expected_type, label)
    } else {
        Ok(DecodedPayload {
            payload: payload.bytes.clone(),
            signer: None,
        })
    }
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content file fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope};
    use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
    use topo::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::facts::content::file::fact::{ContentFileFact, FILE_ROOT_HASH_BYTES};
    use topo::protocol::facts::content::file::{layout, project, rows};
    use topo::protocol::facts::content::sealed_message::{
        fact::{SealedMessageFact, CIPHERTEXT_BYTES, NONCE_BYTES, UNIX_MINUTE_MS},
        layout as sealed_message_layout,
    };
    use topo::protocol::matchers::ExactSelectorMatcher;

    use topo::protocol::facts::identity::user::{fact::UserFact, layout as user_layout};
    use topo::protocol::matchers as message_context;

    #[test]
    fn content_file_projector_materializes_row_through_atomic_intent() {
        let parent_author = user_fact([9; 32], [44; 32], "parent-author");
        let file_author = user_fact([9; 32], [22; 32], "file-author");
        let parent_fact = sealed_parent_fact([9; 32], parent_author.id, 12_000);
        let file = ContentFileFact {
            workspace_id: [9; 32],
            created_at_ms: 12345,
            message_id: parent_fact.id,
            author_user_id: file_author.id,
            file_id: [33; 32],
            blob_bytes: 1_048_576,
            total_slices: 4,
            slice_bytes: 262_144,
            root_hash: [44; FILE_ROOT_HASH_BYTES],
            sealed_metadata: b"sealed-filename-and-mime".to_vec(),
        };
        let fact = Fact::new(
            message_context::workspace_scope(file.workspace_id),
            file.created_at_ms,
            layout::encode_fact(&file).expect("encode file"),
        );
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();

        let matcher = ExactSelectorMatcher::new(message_context::message_role());
        let user_matcher = ExactSelectorMatcher::new(crate::protocol::matchers::user_role());

        assert!(bus.submit_fact(parent_author));
        assert!(bus.submit_fact(file_author));
        assert!(bus.submit_fact(fact.clone()));
        assert!(bus.submit_fact(parent_fact));
        let projected = bus
            .drain_applying_atomic_rows(
                &CombinedProjector,
                &[&matcher, &user_matcher],
                &store,
                &[rows::FILE_ROWS],
                10,
            )
            .expect("project file");
        assert!(projected.projections >= 4);
        assert_eq!(projected.intents, 2);
        assert_eq!(bus.intents().len(), 1);

        let table = store.table_rows(rows::FILE_ROWS).expect("file rows");
        assert_eq!(table.len(), 1);
        let row = rows::decode_content_file_row(&table[0].0, &table[0].1).expect("decode file row");
        assert_eq!(row.workspace_id, file.workspace_id);
        assert_eq!(row.file_fact_id, fact.id);
        assert_eq!(row.created_at_ms, 12345);
        assert_eq!(row.message_id, file.message_id);
        assert_eq!(row.author_user_id, file.author_user_id);
        assert_eq!(row.file_id, file.file_id);
        assert_eq!(row.blob_bytes, file.blob_bytes);
        assert_eq!(row.total_slices, file.total_slices);
        assert_eq!(row.slice_bytes, file.slice_bytes);
        assert_eq!(row.root_hash, file.root_hash);
        assert_eq!(row.sealed_metadata, file.sealed_metadata);
    }

    #[test]
    fn content_file_projector_waits_for_parent_message_context() {
        let file = ContentFileFact {
            workspace_id: [9; 32],
            created_at_ms: 12345,
            message_id: [11; 32],
            author_user_id: [22; 32],
            file_id: [33; 32],
            blob_bytes: 1_048_576,
            total_slices: 4,
            slice_bytes: 262_144,
            root_hash: [44; FILE_ROOT_HASH_BYTES],
            sealed_metadata: b"sealed-filename-and-mime".to_vec(),
        };
        let fact = Fact::new(
            message_context::workspace_scope(file.workspace_id),
            file.created_at_ms,
            layout::encode_fact(&file).expect("encode file"),
        );
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &project::ContentFileProjector::new(),
                &[],
                &store,
                &[rows::FILE_ROWS],
                10,
            )
            .expect("project file");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 0);
        let context = bus.context(&fact.id).expect("file context");
        assert_eq!(context.needs.len(), 3);
        assert!(context
            .needs
            .iter()
            .any(|need| need.role == message_context::message_role()));
        assert!(context
            .needs
            .iter()
            .any(|need| need.role == message_context::deletion_role()));
        assert!(context
            .needs
            .iter()
            .any(|need| need.role == crate::protocol::matchers::user_role()));
        assert!(store
            .table_rows(rows::FILE_ROWS)
            .expect("file rows")
            .is_empty());
    }

    #[test]
    fn content_file_parent_offer_before_need_wakes_file() {
        let parent_author = user_fact([9; 32], [44; 32], "parent-author");
        let file_author = user_fact([9; 32], [22; 32], "file-author");
        let parent_fact = sealed_parent_fact([9; 32], parent_author.id, 12_000);
        let file = ContentFileFact {
            workspace_id: [9; 32],
            created_at_ms: 12345,
            message_id: parent_fact.id,
            author_user_id: file_author.id,
            file_id: [33; 32],
            blob_bytes: 1_048_576,
            total_slices: 4,
            slice_bytes: 262_144,
            root_hash: [44; FILE_ROOT_HASH_BYTES],
            sealed_metadata: b"sealed-filename-and-mime".to_vec(),
        };
        let fact = Fact::new(
            message_context::workspace_scope(file.workspace_id),
            file.created_at_ms,
            layout::encode_fact(&file).expect("encode file"),
        );
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();
        let matcher = ExactSelectorMatcher::new(message_context::message_role());
        let user_matcher = ExactSelectorMatcher::new(crate::protocol::matchers::user_role());

        assert!(bus.submit_fact(parent_author));
        assert!(bus.submit_fact(parent_fact));
        bus.drain_applying_atomic_rows(
            &CombinedProjector,
            &[&matcher, &user_matcher],
            &store,
            &[rows::FILE_ROWS],
            10,
        )
        .expect("project parent first");

        assert!(bus.submit_fact(file_author));
        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &CombinedProjector,
                &[&matcher, &user_matcher],
                &store,
                &[rows::FILE_ROWS],
                10,
            )
            .expect("parent offer wakes file need");

        assert!(projected.projections >= 2);
        assert_eq!(projected.intents, 2);
        let table = store.table_rows(rows::FILE_ROWS).expect("file rows");
        assert_eq!(table.len(), 1);
        let row = rows::decode_content_file_row(&table[0].0, &table[0].1).expect("decode file row");
        assert_eq!(row.file_fact_id, fact.id);
    }

    #[test]
    fn content_file_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
        let mut bus = WakeLoop::new();
        bus.submit_fact(fact);
        let err = bus
            .drain(&project::ContentFileProjector::new(), &[], 10)
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("file") || err.to_lowercase().contains("length"),
            "{err}"
        );
    }

    struct CombinedProjector;

    impl Projector for CombinedProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            match fact.bytes.first().copied() {
                Some(sealed_message_layout::TYPE_SEALED_MESSAGE) => Ok(ProjectionOutput::new()
                    .offer(message_context::message_offer(
                        fact.id,
                        fact.scope.clone(),
                        fact.id,
                    ))),
                Some(layout::TYPE_CONTENT_FILE) => {
                    project::ContentFileProjector::new().project(fact, context)
                }
                _ if crate::protocol::facts::identity::user::decode_fact_payload(fact.body())
                    .is_ok() =>
                {
                    Ok(
                        ProjectionOutput::new().offer(crate::protocol::matchers::exact_offer(
                            fact.id,
                            crate::protocol::matchers::user_role(),
                        )),
                    )
                }
                _ => Err("unknown combined content file test fact".to_string()),
            }
        }
    }

    fn user_fact(workspace_id: [u8; 32], public_key: [u8; 32], username: &str) -> Fact {
        let user = UserFact {
            created_at_ms: 12_000,
            workspace_id,
            public_key,
            username: username.to_string(),
        };
        Fact::new(
            FactScope::Global,
            user.created_at_ms,
            user_layout::encode_fact(&user).expect("encode user"),
        )
    }

    fn sealed_parent_fact(
        workspace_id: [u8; 32],
        author_user_id: [u8; 32],
        created_at_ms: u64,
    ) -> Fact {
        let message = SealedMessageFact {
            workspace_id,
            created_at_ms,
            author_user_id,
            signer_id: [6; 32],
            frontier_id: [7; 32],
            local_history_node_secret_id: [0; 32],
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [0; 32],
            minute: created_at_ms / UNIX_MINUTE_MS,
            leaf_id: [8; 32],
            nonce: [9; NONCE_BYTES],
            ciphertext: vec![0xaa; CIPHERTEXT_BYTES],
        };
        Fact::new(
            message_context::workspace_scope(workspace_id),
            created_at_ms,
            sealed_message_layout::encode_sealed_message(&message)
                .expect("encode sealed parent message"),
        )
    }
}
