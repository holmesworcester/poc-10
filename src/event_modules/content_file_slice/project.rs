//! Poc-10 content-file-slice projector.
//!
//! Decodes a content-file-slice fact and emits a single `PutRow` into
//! `file_slice_rows`. The slice event id used in the row value is the fact id;
//! the key is workspace/file/slice-index so range scans return slices in order.
//!
//! Parity gaps (intentional, deferred to later slices):
//! - Signed-envelope verification (separate event module).
//! - BAO proof verification against the parent descriptor's root hash —
//!   depends on the file-send command wave reintroducing the proof slot.
//! - Parent descriptor existence and slice-index bounds are validated from
//!   matched file context; broader slice-budget enforcement remains in the
//!   file-send command wave.
//! - Per-slice nonce derivation and AEAD opening — owned by the encryption
//!   module, surfaces alongside the per-file content key.

use crate::core::context::ContextNeed;
use crate::core::facts::Fact;
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::content_file::{layout as file_layout, matchers as file_matchers};
use crate::event_modules::content_message::matchers as message_matchers;

use super::layout;
use super::rows::{content_file_slice_key, content_file_slice_row, FILE_SLICE_ROWS};

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
        let slice = layout::decode_fact(&fact.bytes)?;
        let scope = message_matchers::workspace_scope(slice.workspace_id);
        require_fact_scope(fact, &scope)?;
        let file_need = file_matchers::file_need(fact.id, scope.clone(), slice.file_id);
        let Some(parent) = payload_for_need(context, &file_need) else {
            return Ok(ProjectionOutput::new().need(file_need));
        };
        let file = file_layout::decode_fact(&parent.bytes)
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
        if slice.slice_index >= file.total_slices {
            return Err("file slice index is out of range for parent file".to_string());
        }
        let file_deletion_need =
            message_matchers::deletion_need(fact.id, scope, parent.id, file.author_user_id);
        if let Some(deletion) = payload_for_need(context, &file_deletion_need) {
            validate_file_deletion(deletion, file.workspace_id, parent.id, file.author_user_id)?;
            return Ok(ProjectionOutput::new()
                .need(file_need)
                .need(file_deletion_need)
                .intent(
                    AtomicIntent::DeleteRow(TableDelete {
                        table: FILE_SLICE_ROWS,
                        key: content_file_slice_key(
                            &slice.workspace_id,
                            &slice.file_id,
                            slice.slice_index,
                        ),
                    })
                    .into_intent(),
                ));
        }
        Ok(ProjectionOutput::new()
            .need(file_need)
            .need(file_deletion_need)
            .intent(AtomicIntent::PutRow(content_file_slice_row(fact.id, &slice)?).into_intent()))
    }
}

fn payload_for_need<'a>(
    context: &'a ProjectionContext,
    need: &ContextNeed,
) -> Option<&'a Fact> {
    // The wake loop guarantees `payload.id == offer.owner` because each
    // projector can only offer its own fact; no defensive equality check needed.
    context.payload_for(need)
}

fn validate_file_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_file_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion = crate::event_modules::content_file_deletion::layout::decode_fact(&payload.bytes)
        .map_err(|_| {
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

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content file slice fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::matchers::ExactSelectorMatcher;
    use topo::core::projection::{MatchedContext, ProjectionContext, ProjectionOutput, Projector};
    use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::event_modules::content_file::fact::{ContentFileFact, FILE_ROOT_HASH_BYTES};
    use topo::event_modules::content_file::{layout as file_layout, matchers as file_context};
    use topo::event_modules::content_file_deletion::{
        fact::ContentFileDeletionFact, layout as file_deletion_layout,
    };
    use topo::event_modules::content_file_slice::fact::ContentFileSliceFact;
    use topo::event_modules::content_file_slice::{layout, project, rows};
    use topo::event_modules::content_message::fact::ContentMessageFact;
    use topo::event_modules::content_message::{
        layout as message_layout, matchers as message_context,
    };
    use topo::event_modules::identity_matchers;
    use topo::event_modules::identity_user::{fact::UserFact, layout as user_layout};

    #[test]
    fn content_file_slice_projector_materializes_row_through_atomic_intent() {
        let parent_author = user_fact([9; 32], [8; 32], "parent-author");
        let file_author = user_fact([9; 32], [12; 32], "file-author");
        let parent = ContentMessageFact {
            workspace_id: [9; 32],
            author_user_id: parent_author.id,
            created_at_ms: 1000,
            frontier_id: [7; 32],
            minute: 0,
            leaf_id: [6; 32],
            sealed_body_ref: [5; 32],
        };
        let parent_fact = Fact::new(
            message_context::workspace_scope(parent.workspace_id),
            parent.created_at_ms,
            message_layout::encode_fact(&parent).expect("encode parent message"),
        );
        let file = ContentFileFact {
            workspace_id: parent.workspace_id,
            created_at_ms: 1234,
            message_id: parent_fact.id,
            file_id: [11; 32],
            author_user_id: file_author.id,
            blob_bytes: 128,
            total_slices: 4,
            slice_bytes: 32,
            root_hash: [13; FILE_ROOT_HASH_BYTES],
            sealed_metadata: b"sealed".to_vec(),
        };
        let file_fact = Fact::new(
            message_context::workspace_scope(file.workspace_id),
            file.created_at_ms,
            file_layout::encode_fact(&file).expect("encode file"),
        );
        let slice = ContentFileSliceFact {
            workspace_id: [9; 32],
            created_at_ms: 4242,
            file_id: file.file_id,
            slice_index: 3,
            ciphertext: vec![0xaa; 128],
        };
        let fact = Fact::new(
            message_context::workspace_scope(slice.workspace_id),
            slice.created_at_ms,
            layout::encode_fact(&slice).expect("encode slice"),
        );
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        let message_matcher = ExactSelectorMatcher::new(message_context::message_role());
        let file_matcher = ExactSelectorMatcher::new(file_context::file_role());
        let user_matcher = ExactSelectorMatcher::new(identity_matchers::user_role());

        assert!(bus.submit_fact(parent_author));
        assert!(bus.submit_fact(file_author));
        assert!(bus.submit_fact(fact.clone()));
        assert!(bus.submit_fact(parent_fact));
        assert!(bus.submit_fact(file_fact));
        let projected = bus
            .drain_applying_atomic_rows(
                &CombinedProjector,
                &[&message_matcher, &file_matcher, &user_matcher],
                &store,
                &[
                    rows::FILE_SLICE_ROWS,
                    topo::event_modules::content_file::rows::FILE_ROWS,
                    topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
                ],
                10,
            )
            .expect("project slice");
        assert!(projected.projections >= 5);
        assert_eq!(projected.intents, 3);
        assert!(bus.intents().is_empty());

        let table = store
            .table_rows(rows::FILE_SLICE_ROWS)
            .expect("file slice rows");
        assert_eq!(table.len(), 1);
        let row = rows::decode_content_file_slice_row(&table[0].0, &table[0].1)
            .expect("decode slice row");
        assert_eq!(row.workspace_id, slice.workspace_id);
        assert_eq!(row.file_id, slice.file_id);
        assert_eq!(row.slice_index, slice.slice_index);
        assert_eq!(row.slice_event_id, fact.id);
        assert_eq!(row.created_at_ms, 4242);
        assert_eq!(row.ciphertext, slice.ciphertext);
    }

    #[test]
    fn content_file_slice_projector_waits_for_parent_file_context() {
        let slice = ContentFileSliceFact {
            workspace_id: [9; 32],
            created_at_ms: 4242,
            file_id: [11; 32],
            slice_index: 3,
            ciphertext: vec![0xaa; 128],
        };
        let fact = Fact::new(
            message_context::workspace_scope(slice.workspace_id),
            slice.created_at_ms,
            layout::encode_fact(&slice).expect("encode slice"),
        );
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &project::ContentFileSliceProjector::new(),
                &[],
                &store,
                &[rows::FILE_SLICE_ROWS],
                10,
            )
            .expect("project slice");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 0);
        let context = bus.context(&fact.id).expect("slice context");
        assert_eq!(context.needs.len(), 1);
        assert_eq!(context.needs[0].role, file_context::file_role());
        assert!(store
            .table_rows(rows::FILE_SLICE_ROWS)
            .expect("slice rows")
            .is_empty());
    }

    #[test]
    fn content_file_slice_file_offer_before_need_wakes_slice() {
        let parent_author = user_fact([9; 32], [8; 32], "parent-author");
        let file_author = user_fact([9; 32], [12; 32], "file-author");
        let parent = ContentMessageFact {
            workspace_id: [9; 32],
            author_user_id: parent_author.id,
            created_at_ms: 1000,
            frontier_id: [7; 32],
            minute: 0,
            leaf_id: [6; 32],
            sealed_body_ref: [5; 32],
        };
        let parent_fact = Fact::new(
            message_context::workspace_scope(parent.workspace_id),
            parent.created_at_ms,
            message_layout::encode_fact(&parent).expect("encode parent message"),
        );
        let file = ContentFileFact {
            workspace_id: parent.workspace_id,
            created_at_ms: 1234,
            message_id: parent_fact.id,
            file_id: [11; 32],
            author_user_id: file_author.id,
            blob_bytes: 128,
            total_slices: 4,
            slice_bytes: 32,
            root_hash: [13; FILE_ROOT_HASH_BYTES],
            sealed_metadata: b"sealed".to_vec(),
        };
        let file_fact = Fact::new(
            message_context::workspace_scope(file.workspace_id),
            file.created_at_ms,
            file_layout::encode_fact(&file).expect("encode file"),
        );
        let slice = ContentFileSliceFact {
            workspace_id: [9; 32],
            created_at_ms: 4242,
            file_id: file.file_id,
            slice_index: 3,
            ciphertext: vec![0xaa; 128],
        };
        let fact = Fact::new(
            message_context::workspace_scope(slice.workspace_id),
            slice.created_at_ms,
            layout::encode_fact(&slice).expect("encode slice"),
        );
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();
        let message_matcher = ExactSelectorMatcher::new(message_context::message_role());
        let file_matcher = ExactSelectorMatcher::new(file_context::file_role());
        let user_matcher = ExactSelectorMatcher::new(identity_matchers::user_role());

        assert!(bus.submit_fact(parent_author));
        assert!(bus.submit_fact(file_author));
        assert!(bus.submit_fact(parent_fact));
        assert!(bus.submit_fact(file_fact));
        bus.drain_applying_atomic_rows(
            &CombinedProjector,
            &[&message_matcher, &file_matcher, &user_matcher],
            &store,
            &[
                rows::FILE_SLICE_ROWS,
                topo::event_modules::content_file::rows::FILE_ROWS,
                topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
            ],
            10,
        )
        .expect("project file first");

        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &CombinedProjector,
                &[&message_matcher, &file_matcher, &user_matcher],
                &store,
                &[
                    rows::FILE_SLICE_ROWS,
                    topo::event_modules::content_file::rows::FILE_ROWS,
                    topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
                ],
                10,
            )
            .expect("file offer wakes slice need");

        assert!(projected.projections >= 2);
        assert_eq!(projected.intents, 1);
        let table = store
            .table_rows(rows::FILE_SLICE_ROWS)
            .expect("file slice rows");
        assert_eq!(table.len(), 1);
        let row = rows::decode_content_file_slice_row(&table[0].0, &table[0].1)
            .expect("decode slice row");
        assert_eq!(row.slice_event_id, fact.id);
    }

    #[test]
    fn content_file_slice_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
        let mut bus = WakeLoop::new();
        bus.submit_fact(fact);
        let err = bus
            .drain(&project::ContentFileSliceProjector::new(), &[], 10)
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("slice") || err.to_lowercase().contains("length"),
            "{err}"
        );
    }

    #[test]
    fn content_file_slice_deletes_row_when_parent_file_deletion_matches() {
        let workspace_id = [9; 32];
        let file = ContentFileFact {
            workspace_id,
            created_at_ms: 1234,
            message_id: [10; 32],
            file_id: [11; 32],
            author_user_id: [12; 32],
            blob_bytes: 128,
            total_slices: 4,
            slice_bytes: 32,
            root_hash: [13; FILE_ROOT_HASH_BYTES],
            sealed_metadata: b"sealed".to_vec(),
        };
        let file_fact = Fact::new(
            message_context::workspace_scope(workspace_id),
            file.created_at_ms,
            file_layout::encode_fact(&file).expect("encode file"),
        );
        let deletion = ContentFileDeletionFact {
            workspace_id,
            created_at_ms: 2_000,
            target_file_id: file_fact.id,
            author_user_id: file.author_user_id,
        };
        let deletion_fact = Fact::new(
            message_context::workspace_scope(workspace_id),
            deletion.created_at_ms,
            file_deletion_layout::encode_fact(&deletion).expect("encode deletion"),
        );
        let slice = ContentFileSliceFact {
            workspace_id,
            created_at_ms: 4242,
            file_id: file.file_id,
            slice_index: 3,
            ciphertext: vec![0xaa; 128],
        };
        let fact = Fact::new(
            message_context::workspace_scope(slice.workspace_id),
            slice.created_at_ms,
            layout::encode_fact(&slice).expect("encode slice"),
        );
        let scope = message_context::workspace_scope(workspace_id);
        let context = ProjectionContext::from_matches(vec![
            MatchedContext {
                need: file_context::file_need(fact.id, scope.clone(), file.file_id),
                offer: file_context::file_offer(file_fact.id, scope.clone(), file.file_id),
                payload: file_fact.clone(),
            },
            MatchedContext {
                need: message_context::deletion_need(
                    fact.id,
                    scope.clone(),
                    file_fact.id,
                    file.author_user_id,
                ),
                offer: message_context::deletion_offer(
                    deletion_fact.id,
                    scope,
                    file_fact.id,
                    file.author_user_id,
                ),
                payload: deletion_fact,
            },
        ]);

        let output = project::ContentFileSliceProjector::new()
            .project(&fact, &context)
            .expect("project slice deletion");

        assert_eq!(output.needs.len(), 2);
        assert_eq!(output.intents.len(), 1);
        let AtomicIntent::DeleteRow(delete) =
            AtomicIntent::from_intent(&output.intents[0], &[rows::FILE_SLICE_ROWS])
                .expect("delete row intent")
        else {
            panic!("expected delete row");
        };
        assert_eq!(
            delete.key,
            rows::content_file_slice_key(&workspace_id, &file.file_id, slice.slice_index)
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
                Some(file_layout::TYPE_CONTENT_FILE) => {
                    topo::event_modules::content_file::project::ContentFileProjector::new()
                        .project(fact, context)
                }
                Some(layout::TYPE_CONTENT_FILE_SLICE) => {
                    project::ContentFileSliceProjector::new().project(fact, context)
                }
                _ if user_layout::decode_fact(&fact.bytes).is_ok() => Ok(ProjectionOutput::new()
                    .offer(identity_matchers::exact_offer(
                        fact.id,
                        identity_matchers::user_role(),
                    ))),
                _ => Err("unknown combined content file slice test fact".to_string()),
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
