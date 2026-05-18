//! Poc-10 content-file-deletion projector.
//!
//! Decodes a deletion fact, waits for validated target-file and author-user
//! context, then emits a deletion row and `content_deleted` offer. Physical
//! cleanup remains handler work; this projector only materializes authorized
//! deletion state.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::content_file::layout as file_layout;
use crate::event_modules::content_message::authority::{self, DecodedPayload};
use crate::event_modules::content_message::matchers;
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::signed_fact;
use crate::event_modules::sync;

use super::layout;
use super::rows::{file_deletion_row, FileDeletionRow};

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
        let decoded = authority::decode_raw_or_signed(
            fact,
            layout::TYPE_CONTENT_FILE_DELETION,
            "file deletion",
        )?;
        let deletion = layout::decode_fact(&decoded.payload)?;
        let scope = matchers::workspace_scope(deletion.workspace_id);
        require_fact_scope(fact, &scope)?;
        let signer_need = authority::signer_need(fact.id, decoded.signer);
        let target_need =
            sync::matchers::exact_event_need(fact.id, scope.clone(), deletion.target_file_id);
        let author_need = identity_matchers::exact_need(
            fact.id,
            identity_matchers::user_role(),
            deletion.author_user_id,
        );
        if let (Some(signer), Some(need)) = (decoded.signer, signer_need.as_ref()) {
            if !authority::validate_signer_context(
                context,
                need,
                signer,
                deletion.workspace_id,
                Some(deletion.author_user_id),
                "file deletion",
            )? {
                return Ok(output_with_needs([
                    signer_need,
                    Some(target_need),
                    Some(author_need),
                ]));
            }
        }
        authority::verify_signature(&decoded, "file deletion")?;
        let Some(target_fact) = payload_for_need(context, &target_need) else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(author_need),
            ]));
        };
        let Some(author_fact) = payload_for_need(context, &author_need) else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(author_need),
            ]));
        };
        validate_target_file(&deletion, target_fact, &scope)?;
        validate_author_user(&deletion, author_fact)?;
        let row = file_deletion_row(FileDeletionRow {
            workspace_id: deletion.workspace_id,
            target_file_id: deletion.target_file_id,
            deletion_id: fact.id,
            created_at_ms: deletion.created_at_ms,
            author_user_id: deletion.author_user_id,
        })?;
        Ok(
            output_with_needs([signer_need, Some(target_need), Some(author_need)])
                .offer(matchers::deletion_offer(
                    fact.id,
                    scope,
                    deletion.target_file_id,
                    deletion.author_user_id,
                ))
                .intent(AtomicIntent::PutRow(row).into_intent()),
        )
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

fn validate_target_file(
    deletion: &super::fact::ContentFileDeletionFact,
    target_fact: &Fact,
    expected_scope: &FactScope,
) -> Result<(), String> {
    if target_fact.id != deletion.target_file_id {
        return Err("file deletion target context payload id mismatch".to_string());
    }
    if &target_fact.scope != expected_scope {
        return Err("file deletion target scope does not match deletion".to_string());
    }
    let target_payload = maybe_signed_payload(
        target_fact,
        file_layout::TYPE_CONTENT_FILE,
        "file deletion target",
    )?;
    let target = file_layout::decode_fact(&target_payload.payload)
        .map_err(|_| "file deletion target context must be a content file".to_string())?;
    if target.workspace_id != deletion.workspace_id {
        return Err("file deletion target workspace does not match deletion".to_string());
    }
    if target.author_user_id != deletion.author_user_id {
        return Err("file deletion author is not the target file author".to_string());
    }
    Ok(())
}

fn validate_author_user(
    deletion: &super::fact::ContentFileDeletionFact,
    author_fact: &Fact,
) -> Result<(), String> {
    if author_fact.id != deletion.author_user_id {
        return Err("file deletion author context payload id mismatch".to_string());
    }
    let author_payload =
        maybe_signed_payload(author_fact, user_layout::TYPE_USER, "file deletion author")?;
    let author = user_layout::decode_fact(&author_payload.payload)
        .map_err(|_| "file deletion author context must be an identity user".to_string())?;
    if author.workspace_id != deletion.workspace_id {
        return Err("file deletion author workspace does not match deletion".to_string());
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
        Err("content file deletion fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactId, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::core::wake_loop::WakeLoop;
    use topo::event_modules::content_file::fact::{ContentFileFact, FILE_ROOT_HASH_BYTES};
    use topo::event_modules::content_file::layout as file_layout;
    use topo::event_modules::content_file_deletion::fact::ContentFileDeletionFact;
    use topo::event_modules::content_file_deletion::{layout, project, rows};
    use topo::event_modules::content_message::matchers as message_context;
    use topo::event_modules::identity_matchers;
    use topo::event_modules::identity_user::{fact::UserFact, layout as user_layout};
    use topo::event_modules::sync::matchers as sync_matchers;

    #[test]
    fn content_file_deletion_projector_materializes_row_through_atomic_intent() {
        let workspace_id = [9; 32];
        let author = user_fact(workspace_id, [22; 32], "alice");
        let target = file_fact(workspace_id, author.id);
        let (deletion, fact) = deletion_fact(workspace_id, target.id, author.id, 54_321);

        let output = project::ContentFileDeletionProjector::new()
            .project(&fact, &authorized_context(&fact, &target, &author))
            .expect("project deletion");

        assert_eq!(output.needs.len(), 2);
        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].role, message_context::deletion_role());
        assert_eq!(output.intents.len(), 1);
        let AtomicIntent::PutRow(stored) =
            AtomicIntent::from_intent(&output.intents[0], &[rows::FILE_DELETION_ROWS])
                .expect("row intent")
        else {
            panic!("expected put row intent");
        };
        let row = rows::decode_file_deletion_row(&stored.key, &stored.value)
            .expect("decode file deletion row");
        assert_eq!(row.workspace_id, deletion.workspace_id);
        assert_eq!(row.target_file_id, deletion.target_file_id);
        assert_eq!(row.deletion_id, fact.id);
        assert_eq!(row.created_at_ms, 54_321);
        assert_eq!(row.author_user_id, deletion.author_user_id);
    }

    #[test]
    fn content_file_deletion_projector_waits_for_target_and_author_context() {
        let (deletion, fact) = deletion_fact([9; 32], [11; 32], [22; 32], 54_321);

        let output = project::ContentFileDeletionProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("missing context is a need");

        assert!(output.intents.is_empty());
        assert!(output.offers.is_empty());
        assert_eq!(output.needs.len(), 2);
        assert!(output.needs.contains(&sync_matchers::exact_event_need(
            fact.id,
            message_context::workspace_scope(deletion.workspace_id),
            deletion.target_file_id
        )));
        assert!(output.needs.contains(&identity_matchers::exact_need(
            fact.id,
            identity_matchers::user_role(),
            deletion.author_user_id
        )));
    }

    #[test]
    fn content_file_deletion_projector_rejects_non_author_delete() {
        let workspace_id = [9; 32];
        let file_author = user_fact(workspace_id, [22; 32], "alice");
        let deleter = user_fact(workspace_id, [44; 32], "mallory");
        let target = file_fact(workspace_id, file_author.id);
        let (_deletion, fact) = deletion_fact(workspace_id, target.id, deleter.id, 54_321);

        let err = project::ContentFileDeletionProjector::new()
            .project(&fact, &authorized_context(&fact, &target, &deleter))
            .expect_err("non-author deletion must reject");

        assert!(err.contains("not the target file author"), "{err}");
    }

    #[test]
    fn content_file_deletion_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
        let mut bus = WakeLoop::new();
        bus.submit_fact(fact);
        let err = bus
            .drain(&project::ContentFileDeletionProjector::new(), &[], 10)
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("deletion") || err.to_lowercase().contains("length"),
            "{err}"
        );
    }

    fn deletion_fact(
        workspace_id: FactId,
        target_file_id: FactId,
        author_user_id: FactId,
        created_at_ms: u64,
    ) -> (ContentFileDeletionFact, Fact) {
        let deletion = ContentFileDeletionFact {
            workspace_id,
            created_at_ms,
            target_file_id,
            author_user_id,
        };
        let fact = Fact::new(
            message_context::workspace_scope(deletion.workspace_id),
            deletion.created_at_ms,
            layout::encode_fact(&deletion).expect("encode deletion"),
        );
        (deletion, fact)
    }

    fn file_fact(workspace_id: FactId, author_user_id: FactId) -> Fact {
        let file = ContentFileFact {
            workspace_id,
            created_at_ms: 12_345,
            message_id: [88; 32],
            author_user_id,
            file_id: [33; 32],
            blob_bytes: 1_024,
            total_slices: 1,
            slice_bytes: 1_024,
            root_hash: [44; FILE_ROOT_HASH_BYTES],
            sealed_metadata: b"sealed".to_vec(),
        };
        Fact::new(
            message_context::workspace_scope(file.workspace_id),
            file.created_at_ms,
            file_layout::encode_fact(&file).expect("encode file"),
        )
    }

    fn user_fact(workspace_id: FactId, public_key: [u8; 32], username: &str) -> Fact {
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

    fn authorized_context(
        deletion_fact: &Fact,
        target_fact: &Fact,
        author_fact: &Fact,
    ) -> ProjectionContext {
        ProjectionContext::from_matches(vec![
            MatchedContext {
                need: sync_matchers::exact_event_need(
                    deletion_fact.id,
                    target_fact.scope.clone(),
                    target_fact.id,
                ),
                offer: sync_matchers::exact_event_offer(
                    target_fact.id,
                    target_fact.scope.clone(),
                    target_fact.id,
                ),
                payload: target_fact.clone(),
            },
            MatchedContext {
                need: identity_matchers::exact_need(
                    deletion_fact.id,
                    identity_matchers::user_role(),
                    author_fact.id,
                ),
                offer: identity_matchers::exact_offer(
                    author_fact.id,
                    identity_matchers::user_role(),
                ),
                payload: author_fact.clone(),
            },
        ])
    }
}
