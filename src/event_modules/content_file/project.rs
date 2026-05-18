//! Poc-10 content-file projector.
//!
//! Decodes a content-file fact and emits a single `PutRow` into `file_rows`.
//! The file event id used in the row key is the fact id.
//!
//! Signed content-file facts are parsed up front so the signer need can be
//! emitted, but signature verification waits until endpoint signer context is
//! available. Parent-message and author-user authority are validated through
//! context before rows are materialized. Parent or file deletion context purges
//! the descriptor row instead of recreating it.
//!
//! Parity gaps (intentional, deferred to later slices):
//! - Per-file leaf-coord / frontier derivation — depends on per-message FS.
//! - Sealed-metadata AEAD opening — depends on encryption module surfacing the
//!   per-file content key.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::content_message::authority::{self, DecodedPayload};
use crate::event_modules::content_message::{
    layout as message_layout, matchers as message_matchers,
};
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::signed_fact;
use crate::event_modules::sync;

use super::fact::MAX_FILE_BYTES;
use super::layout;
use super::matchers;
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
        let decoded =
            authority::decode_raw_or_signed(fact, layout::TYPE_CONTENT_FILE, "content file")?;
        let file = layout::decode_fact(&decoded.payload)?;
        validate_file_fields(&file)?;
        let scope = message_matchers::workspace_scope(file.workspace_id);
        require_fact_scope(fact, &scope)?;
        let signer_need = authority::signer_need(fact.id, decoded.signer);
        let file_deletion_need =
            message_matchers::deletion_need(fact.id, scope.clone(), fact.id, file.author_user_id);
        let parent_need = message_matchers::message_need(fact.id, scope.clone(), file.message_id);
        let author_need = identity_matchers::exact_need(
            fact.id,
            identity_matchers::user_role(),
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
        authority::verify_signature(&decoded, "file")?;
        if let Some(deletion) = payload_for_need(context, &file_deletion_need) {
            validate_file_deletion(deletion, file.workspace_id, fact.id, file.author_user_id)?;
            return Ok(delete_file_projection(file.workspace_id, fact.id).need(file_deletion_need));
        }
        let Some(parent) = payload_for_need(context, &parent_need) else {
            return Ok(output_with_needs([
                signer_need,
                Some(parent_need),
                Some(file_deletion_need),
                Some(author_need),
                None,
            ]));
        };
        validate_parent_message(parent, &scope, file.workspace_id, file.message_id)?;
        let parent_payload =
            maybe_signed_payload(parent, message_layout::TYPE_CONTENT_MESSAGE, "file parent")?;
        let parent_message = message_layout::decode_fact(&parent_payload.payload)
            .map_err(|_| "file parent context is not a content message".to_string())?;
        let parent_deletion_need = message_matchers::deletion_need(
            fact.id,
            scope.clone(),
            file.message_id,
            parent_message.author_user_id,
        );
        if let Some(deletion) = payload_for_need(context, &parent_deletion_need) {
            validate_message_deletion(
                deletion,
                file.workspace_id,
                file.message_id,
                parent_message.author_user_id,
            )?;
            return Ok(delete_file_projection(file.workspace_id, fact.id)
                .need(file_deletion_need)
                .need(parent_need)
                .need(parent_deletion_need));
        }
        let Some(author) = payload_for_need(context, &author_need) else {
            return Ok(output_with_needs([
                signer_need,
                Some(file_deletion_need),
                Some(parent_need),
                Some(parent_deletion_need),
                Some(author_need),
            ]));
        };
        validate_author_user(author, file.workspace_id, file.author_user_id)?;
        Ok(output_with_needs([
            signer_need,
            Some(file_deletion_need),
            Some(parent_need),
            Some(parent_deletion_need),
            Some(author_need),
        ])
        .offer(matchers::file_offer(fact.id, scope, file.file_id))
        .offer(sync::matchers::exact_event_offer(
            fact.id,
            message_matchers::workspace_scope(file.workspace_id),
            fact.id,
        ))
        .intent(AtomicIntent::PutRow(content_file_row(fact.id, &file)?).into_intent()))
    }
}

fn payload_for_need<'a>(
    context: &'a ProjectionContext,
    need: &crate::core::context::ContextNeed,
) -> Option<&'a Fact> {
    authority::payload_for_need(context, need)
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
    file_event_id: crate::core::facts::FactId,
) -> ProjectionOutput {
    ProjectionOutput::new().intent(
        AtomicIntent::DeleteRow(TableDelete {
            table: FILE_ROWS,
            key: content_file_key(&workspace_id, &file_event_id),
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

fn validate_parent_message(
    payload: &Fact,
    expected_scope: &FactScope,
    workspace_id: crate::core::facts::FactId,
    message_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if payload.id != message_id {
        return Err("file parent context payload id mismatch".to_string());
    }
    if &payload.scope != expected_scope {
        return Err("file parent context scope does not match file workspace".to_string());
    }
    let parent_payload =
        maybe_signed_payload(payload, message_layout::TYPE_CONTENT_MESSAGE, "file parent")?;
    let parent = message_layout::decode_fact(&parent_payload.payload)
        .map_err(|_| "file parent context is not a content message".to_string())?;
    if parent.workspace_id != workspace_id {
        return Err("file parent message workspace does not match file".to_string());
    }
    Ok(())
}

fn validate_author_user(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if payload.id != author_user_id {
        return Err("file author context payload id mismatch".to_string());
    }
    let author_payload = maybe_signed_payload(payload, user_layout::TYPE_USER, "file author")?;
    let author = user_layout::decode_fact(&author_payload.payload)
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
        crate::event_modules::content_file_deletion::layout::TYPE_CONTENT_FILE_DELETION,
        "file deletion",
    )?;
    let deletion =
        crate::event_modules::content_file_deletion::layout::decode_fact(&deletion_payload.payload)
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
        crate::event_modules::content_message_deletion::layout::TYPE_CONTENT_MESSAGE_DELETION,
        "parent deletion",
    )?;
    let deletion = crate::event_modules::content_message_deletion::layout::decode_fact(
        &deletion_payload.payload,
    )
    .map_err(|_| "parent deletion context is not a content message deletion".to_string())?;
    if deletion.workspace_id != workspace_id {
        return Err("parent deletion workspace does not match file".to_string());
    }
    if deletion.target_message_id != target_message_id {
        return Err("parent deletion target does not match file parent".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("parent deletion author does not match parent message author".to_string());
    }
    Ok(())
}

fn maybe_signed_payload(
    payload: &Fact,
    expected_type: u8,
    label: &str,
) -> Result<DecodedPayload, String> {
    if payload.bytes.first().copied() == Some(signed_fact::layout::TYPE_SIGNED_FACT) {
        authority::decode_raw_or_signed(payload, expected_type, label)
    } else {
        Ok(DecodedPayload {
            payload: payload.bytes.clone(),
            signer: None,
            envelope: None,
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
    use topo::core::matchers::ExactSelectorMatcher;
    use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
    use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::event_modules::content_file::fact::{ContentFileFact, FILE_ROOT_HASH_BYTES};
    use topo::event_modules::content_file::{layout, project, rows};
    use topo::event_modules::content_message::fact::ContentMessageFact;
    use topo::event_modules::content_message::{
        layout as message_layout, matchers as message_context,
    };
    use topo::event_modules::identity_matchers;
    use topo::event_modules::identity_user::{fact::UserFact, layout as user_layout};

    #[test]
    fn content_file_projector_materializes_row_through_atomic_intent() {
        let parent_author = user_fact([9; 32], [44; 32], "parent-author");
        let file_author = user_fact([9; 32], [22; 32], "file-author");
        let parent = ContentMessageFact {
            workspace_id: [9; 32],
            author_user_id: parent_author.id,
            created_at_ms: 12_000,
            frontier_id: [55; 32],
            minute: 0,
            leaf_id: [66; 32],
            sealed_body_ref: [77; 32],
        };
        let parent_fact = Fact::new(
            message_context::workspace_scope(parent.workspace_id),
            parent.created_at_ms,
            message_layout::encode_fact(&parent).expect("encode parent message"),
        );
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
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        let matcher = ExactSelectorMatcher::new(message_context::message_role());
        let user_matcher = ExactSelectorMatcher::new(identity_matchers::user_role());

        assert!(bus.submit_fact(parent_author));
        assert!(bus.submit_fact(file_author));
        assert!(bus.submit_fact(fact.clone()));
        assert!(bus.submit_fact(parent_fact));
        let projected = bus
            .drain_applying_atomic_rows(
                &CombinedProjector,
                &[&matcher, &user_matcher],
                &store,
                &[
                    rows::FILE_ROWS,
                    topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
                ],
                10,
            )
            .expect("project file");
        assert!(projected.projections >= 4);
        assert_eq!(projected.intents, 2);
        assert!(bus.intents().is_empty());

        let table = store.table_rows(rows::FILE_ROWS).expect("file rows");
        assert_eq!(table.len(), 1);
        let row = rows::decode_content_file_row(&table[0].0, &table[0].1).expect("decode file row");
        assert_eq!(row.workspace_id, file.workspace_id);
        assert_eq!(row.file_event_id, fact.id);
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
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
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
            .any(|need| need.role == identity_matchers::user_role()));
        assert!(store
            .table_rows(rows::FILE_ROWS)
            .expect("file rows")
            .is_empty());
    }

    #[test]
    fn content_file_parent_offer_before_need_wakes_file() {
        let parent_author = user_fact([9; 32], [44; 32], "parent-author");
        let file_author = user_fact([9; 32], [22; 32], "file-author");
        let parent = ContentMessageFact {
            workspace_id: [9; 32],
            author_user_id: parent_author.id,
            created_at_ms: 12_000,
            frontier_id: [55; 32],
            minute: 0,
            leaf_id: [66; 32],
            sealed_body_ref: [77; 32],
        };
        let parent_fact = Fact::new(
            message_context::workspace_scope(parent.workspace_id),
            parent.created_at_ms,
            message_layout::encode_fact(&parent).expect("encode parent message"),
        );
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
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();
        let matcher = ExactSelectorMatcher::new(message_context::message_role());
        let user_matcher = ExactSelectorMatcher::new(identity_matchers::user_role());

        assert!(bus.submit_fact(parent_author));
        assert!(bus.submit_fact(parent_fact));
        bus.drain_applying_atomic_rows(
            &CombinedProjector,
            &[&matcher, &user_matcher],
            &store,
            &[
                rows::FILE_ROWS,
                topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
            ],
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
                &[
                    rows::FILE_ROWS,
                    topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
                ],
                10,
            )
            .expect("parent offer wakes file need");

        assert!(projected.projections >= 2);
        assert_eq!(projected.intents, 1);
        let table = store.table_rows(rows::FILE_ROWS).expect("file rows");
        assert_eq!(table.len(), 1);
        let row = rows::decode_content_file_row(&table[0].0, &table[0].1).expect("decode file row");
        assert_eq!(row.file_event_id, fact.id);
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
                Some(message_layout::TYPE_CONTENT_MESSAGE) => {
                    topo::event_modules::content_message::project::ContentMessageProjector::new()
                        .project(fact, context)
                }
                Some(layout::TYPE_CONTENT_FILE) => {
                    project::ContentFileProjector::new().project(fact, context)
                }
                _ if user_layout::decode_fact(&fact.bytes).is_ok() => Ok(ProjectionOutput::new()
                    .offer(identity_matchers::exact_offer(
                        fact.id,
                        identity_matchers::user_role(),
                    ))),
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
}
