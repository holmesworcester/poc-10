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
        Ok(ProjectionOutput::new()
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
