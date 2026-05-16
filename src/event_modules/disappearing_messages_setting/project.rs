//! Disappearing-messages setting projector (poc-10 target tree).
//!
//! Decodes a setting fact, waits for validated authority and predecessor
//! context, enforces monotonic `retire_minute`, and emits a single `PutRow`.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_admin;
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_workspace;
use crate::event_modules::sync;

use super::fact::DisappearingMessagesSettingFact;
use super::layout;
use super::rows::setting_row;

#[derive(Debug, Clone, Default)]
pub struct DisappearingMessagesSettingProjector;

impl DisappearingMessagesSettingProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for DisappearingMessagesSettingProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let setting = layout::decode_fact(&fact.bytes)?;
        if setting.ttl_minutes == 0 {
            return Err("disappearing setting ttl_minutes must be non-zero".to_string());
        }
        if setting.created_at_ms == 0 {
            return Err("disappearing setting created_at_ms must be non-zero".to_string());
        }
        if setting.scope_kind == super::fact::SCOPE_KIND_WORKSPACE
            && setting.scope_id != setting.workspace_id
        {
            return Err(
                "disappearing setting workspace-scope id must match workspace_id".to_string(),
            );
        }
        let authority_need = if setting.supersedes_setting_id.is_none()
            && setting.author_user_id == setting.workspace_id
        {
            identity_matchers::exact_need(
                fact.id,
                identity_matchers::workspace_role(),
                setting.workspace_id,
            )
        } else {
            identity_matchers::scoped_key_need(
                fact.id,
                identity_matchers::admin_role(),
                setting.workspace_id,
                setting.author_user_id.to_vec(),
            )
        };
        let previous_need = setting.supersedes_setting_id.map(|previous_id| {
            sync::matchers::exact_event_need(fact.id, FactScope::Global, previous_id)
        });
        let mut waiting = ProjectionOutput::new().need(authority_need.clone());
        if let Some(need) = &previous_need {
            waiting = waiting.need(need.clone());
        }

        let Some(authority_fact) = projection_context.payload_for(&authority_need) else {
            return Ok(waiting);
        };
        let previous_fact = if let Some(need) = &previous_need {
            let Some(payload) = projection_context.payload_for(need) else {
                return Ok(waiting);
            };
            Some(payload)
        } else {
            None
        };

        validate_authority(authority_fact, &setting)?;
        if let Some(previous) = previous_fact {
            validate_previous(previous, &setting)?;
        }

        let row = setting_row(fact.id, &setting)?;
        Ok(waiting
            .offer(sync::matchers::exact_event_offer(
                fact.id,
                FactScope::Global,
                fact.id,
                fact.id,
            ))
            .intent(AtomicIntent::PutRow(row).into_intent()))
    }
}

fn validate_authority(
    authority_fact: &Fact,
    setting: &DisappearingMessagesSettingFact,
) -> Result<(), String> {
    if let Ok(admin) = identity_admin::layout::decode_fact(&authority_fact.bytes) {
        if admin.workspace_id != setting.workspace_id {
            return Err("disappearing setting authority admin workspace mismatch".to_string());
        }
        if admin.user_fact_id != setting.author_user_id {
            return Err("disappearing setting authority admin user mismatch".to_string());
        }
        return Ok(());
    }

    if setting.supersedes_setting_id.is_none()
        && authority_fact.id == setting.workspace_id
        && setting.author_user_id == setting.workspace_id
        && identity_workspace::layout::decode_fact(&authority_fact.bytes).is_ok()
    {
        return Ok(());
    }

    Err("disappearing setting authority context is not valid admin authority".to_string())
}

fn validate_previous(
    previous_fact: &Fact,
    setting: &DisappearingMessagesSettingFact,
) -> Result<(), String> {
    if Some(previous_fact.id) != setting.supersedes_setting_id {
        return Err("disappearing setting previous context payload id mismatch".to_string());
    }
    let previous = layout::decode_fact(&previous_fact.bytes)
        .map_err(|_| "disappearing setting previous context must be a setting fact".to_string())?;
    if previous.workspace_id != setting.workspace_id
        || previous.scope_kind != setting.scope_kind
        || previous.scope_id != setting.scope_id
    {
        return Err("disappearing setting previous scope mismatch".to_string());
    }
    if setting.retire_minute < previous.retire_minute {
        return Err("disappearing setting retire_minute regresses previous setting".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::event_modules::disappearing_messages_setting::fact::{
        DisappearingMessagesSettingFact, SCOPE_KIND_CHANNEL, SCOPE_KIND_WORKSPACE,
    };
    use topo::event_modules::disappearing_messages_setting::{layout, project, rows};
    use topo::event_modules::identity_admin::fact::AdminFact;
    use topo::event_modules::identity_admin::layout as admin_layout;
    use topo::event_modules::identity_matchers;
    use topo::event_modules::sync::matchers as sync_matchers;

    fn workspace_setting() -> DisappearingMessagesSettingFact {
        DisappearingMessagesSettingFact {
            workspace_id: [1; 32],
            supersedes_setting_id: None,
            ttl_minutes: 60,
            retire_minute: 12_345,
            scope_kind: SCOPE_KIND_WORKSPACE,
            scope_id: [1; 32],
            author_user_id: [3; 32],
            created_at_ms: 6_000_000,
        }
    }

    #[test]
    fn setting_projector_waits_for_authority_then_materializes_row() {
        let setting = workspace_setting();
        let fact = setting_fact(&setting);
        let authority = admin_fact(setting.workspace_id, setting.author_user_id);
        let projector = project::DisappearingMessagesSettingProjector::new();

        let waiting = projector
            .project(&fact, &ProjectionContext::default())
            .expect("missing authority waits");
        assert!(waiting.intents.is_empty());
        assert_eq!(waiting.needs.len(), 1);

        let projected = projector
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![authority_match(
                    fact.id, &setting, authority,
                )]),
            )
            .expect("project setting");
        assert_eq!(projected.intents.len(), 1);
        assert!(projected
            .offers
            .iter()
            .any(|offer| offer.role == sync_matchers::exact_event_role()));

        let row = decode_single_put_row(&projected.intents[0]);
        assert_eq!(row.workspace_id, setting.workspace_id);
        assert_eq!(row.setting_id, fact.id);
        assert_eq!(row.scope_kind, SCOPE_KIND_WORKSPACE);
        assert_eq!(row.scope_id, setting.workspace_id);
        assert_eq!(row.ttl_minutes, setting.ttl_minutes);
        assert_eq!(row.retire_minute, setting.retire_minute);
        assert_eq!(row.author_user_id, setting.author_user_id);
        assert_eq!(row.supersedes_setting_id, None);
        assert_eq!(row.created_at_ms, setting.created_at_ms);
    }

    #[test]
    fn setting_projector_requires_previous_setting_and_enforces_monotonic_retire_minute() {
        let previous = DisappearingMessagesSettingFact {
            scope_kind: SCOPE_KIND_CHANNEL,
            scope_id: [9; 32],
            retire_minute: 99_000,
            ..workspace_setting()
        };
        let previous_fact = setting_fact(&previous);
        let setting = DisappearingMessagesSettingFact {
            supersedes_setting_id: Some(previous_fact.id),
            retire_minute: 99_999,
            ..previous.clone()
        };
        let fact = setting_fact(&setting);
        let authority = admin_fact(setting.workspace_id, setting.author_user_id);
        let projector = project::DisappearingMessagesSettingProjector::new();

        let waiting = projector
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![authority_match(
                    fact.id,
                    &setting,
                    authority.clone(),
                )]),
            )
            .expect("missing previous waits");
        assert!(waiting.intents.is_empty());
        assert_eq!(waiting.needs.len(), 2);

        let projected = projector
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    authority_match(fact.id, &setting, authority.clone()),
                    previous_match(fact.id, previous_fact.clone()),
                ]),
            )
            .expect("matched previous projects");
        let row = decode_single_put_row(&projected.intents[0]);
        assert_eq!(row.scope_kind, SCOPE_KIND_CHANNEL);
        assert_eq!(row.scope_id, [9; 32]);
        assert_eq!(row.supersedes_setting_id, Some(previous_fact.id));
        assert_eq!(row.retire_minute, 99_999);

        let regressing = DisappearingMessagesSettingFact {
            retire_minute: 98_999,
            ..setting
        };
        let regressing_fact = setting_fact(&regressing);
        let err = projector
            .project(
                &regressing_fact,
                &ProjectionContext::from_matches(vec![
                    authority_match(regressing_fact.id, &regressing, authority),
                    previous_match(regressing_fact.id, previous_fact),
                ]),
            )
            .expect_err("retire_minute regression fails");
        assert!(err.contains("regresses"), "{err}");
    }

    #[test]
    fn setting_projector_rejects_zero_ttl() {
        let mut setting = workspace_setting();
        setting.ttl_minutes = 0;
        let fact = setting_fact(&setting);
        let err = project::DisappearingMessagesSettingProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect_err("zero ttl must fail");
        assert!(err.to_lowercase().contains("ttl"), "{err}");
    }

    #[test]
    fn setting_projector_rejects_workspace_scope_with_mismatched_scope_id() {
        let mut setting = workspace_setting();
        setting.scope_id = [99; 32];
        let fact = setting_fact(&setting);
        let err = project::DisappearingMessagesSettingProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect_err("workspace-scope mismatch must fail");
        assert!(err.to_lowercase().contains("workspace"), "{err}");
    }

    #[test]
    fn setting_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
        let err = project::DisappearingMessagesSettingProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("setting") || err.to_lowercase().contains("length"),
            "{err}"
        );
    }

    fn setting_fact(setting: &DisappearingMessagesSettingFact) -> Fact {
        Fact::new(
            FactScope::Global,
            setting.created_at_ms,
            layout::encode_fact(setting).expect("encode setting"),
        )
    }

    fn admin_fact(workspace_id: [u8; 32], user_fact_id: [u8; 32]) -> Fact {
        Fact::new(
            FactScope::Global,
            1,
            admin_layout::encode_fact(&AdminFact {
                created_at_ms: 1,
                workspace_id,
                public_key: [8; 32],
                authority_fact_id: workspace_id,
                user_fact_id,
            })
            .expect("encode admin"),
        )
    }

    fn authority_match(
        owner: [u8; 32],
        setting: &DisappearingMessagesSettingFact,
        authority: Fact,
    ) -> MatchedContext {
        matched(
            identity_matchers::scoped_key_need(
                owner,
                identity_matchers::admin_role(),
                setting.workspace_id,
                setting.author_user_id.to_vec(),
            ),
            identity_matchers::scoped_key_offer(
                authority.id,
                identity_matchers::admin_role(),
                setting.workspace_id,
                setting.author_user_id.to_vec(),
            ),
            authority,
        )
    }

    fn previous_match(owner: [u8; 32], previous: Fact) -> MatchedContext {
        matched(
            sync_matchers::exact_event_need(owner, FactScope::Global, previous.id),
            sync_matchers::exact_event_offer(
                previous.id,
                FactScope::Global,
                previous.id,
                previous.id,
            ),
            previous,
        )
    }

    fn matched(
        need: topo::core::context::ContextNeed,
        offer: topo::core::context::ContextOffer,
        payload: Fact,
    ) -> MatchedContext {
        MatchedContext {
            need,
            offer,
            payload,
        }
    }

    fn decode_single_put_row(
        intent: &topo::core::intents::Intent,
    ) -> rows::DisappearingMessagesSettingRow {
        match AtomicIntent::from_intent(intent, &[rows::DISAPPEARING_MESSAGES_SETTING_ROWS])
            .expect("row intent")
        {
            AtomicIntent::PutRow(row) => rows::decode_setting_row(&row.key, &row.value)
                .expect("decode disappearing setting row"),
            AtomicIntent::DeleteRow(_) => panic!("expected put row"),
        }
    }
}
