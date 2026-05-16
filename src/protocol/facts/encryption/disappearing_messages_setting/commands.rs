//! Command-facing disappearing-messages setting constructors.
//!
//! These helpers read projected state, compute the monotonic floor, and return
//! a proposed setting fact. Projection and purge execution stay in the target
//! runtime.

use crate::core::command_context::CommandOutput;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::store::Store;
use crate::protocol::facts::{content, identity};

use super::fact::{DisappearingMessagesSettingFact, SCOPE_KIND_WORKSPACE};
use super::{layout, queries};

pub const UNIX_MINUTE_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorSetting {
    pub workspace_id: FactId,
    pub now_ms: u64,
    pub ttl_minutes: u32,
    pub explicit_floor: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorSetReport {
    pub setting_fact_id: FactId,
    pub previous_floor_minute: u64,
    pub new_floor_minute: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorTighten {
    pub workspace_id: FactId,
    pub now_ms: u64,
    pub ttl_minutes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TightenPlan {
    pub previous_floor_minute: u64,
    pub target_floor_minute: u64,
    pub messages_below_floor: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorTightenReport {
    pub setting_fact_id: FactId,
    pub previous_floor_minute: u64,
    pub target_floor_minute: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorCompact {
    pub workspace_id: FactId,
    pub now_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorCompactReport {
    pub setting_fact_id: FactId,
    pub ttl_minutes: u32,
    pub previous_floor_minute: u64,
    pub new_floor_minute: u64,
}

pub fn author_set_with_auto_floor(
    store: &Store,
    input: AuthorSetting,
) -> Result<CommandOutput<AuthorSetReport>, String> {
    if input.ttl_minutes == 0 {
        return Err("disappearing setting ttl_minutes must be non-zero".to_string());
    }
    let author_user_id = local_admin_user_id(store, input.workspace_id)?;
    let previous = queries::active_for_workspace(store, input.workspace_id)?;
    let previous_setting_id = previous.as_ref().map(|row| row.setting_id);
    let previous_floor = previous.as_ref().map(|row| row.retire_minute).unwrap_or(0);
    let now_minute = input.now_ms / UNIX_MINUTE_MS;
    let auto_floor = previous_floor.max(now_minute.saturating_sub(u64::from(input.ttl_minutes)));
    let new_floor = match input.explicit_floor {
        Some(floor) if floor < previous_floor => {
            return Err("disappearing setting floor must be monotonic non-decreasing".to_string());
        }
        Some(floor) => floor,
        None => auto_floor,
    };

    let fact = setting_fact(
        input.workspace_id,
        previous_setting_id,
        input.ttl_minutes,
        new_floor,
        author_user_id,
        input.now_ms,
    )?;
    Ok(CommandOutput::new(AuthorSetReport {
        setting_fact_id: fact.id,
        previous_floor_minute: previous_floor,
        new_floor_minute: new_floor,
    })
    .with_facts(vec![fact]))
}

pub fn plan_tighten(store: &Store, input: AuthorTighten) -> Result<TightenPlan, String> {
    if input.ttl_minutes == 0 {
        return Err("disappearing setting ttl_minutes must be non-zero".to_string());
    }
    let _author_user_id = local_admin_user_id(store, input.workspace_id)?;
    let previous = queries::active_for_workspace(store, input.workspace_id)?;
    let previous_floor = previous.as_ref().map(|row| row.retire_minute).unwrap_or(0);
    let now_minute = input.now_ms / UNIX_MINUTE_MS;
    let target_floor = now_minute.saturating_sub(u64::from(input.ttl_minutes));
    if target_floor < previous_floor {
        return Err(
            "disappearing setting floor must be monotonic non-decreasing (current floor \
             already exceeds now_minute - new_ttl_minutes; use disappearing-set instead)"
                .to_string(),
        );
    }
    Ok(TightenPlan {
        previous_floor_minute: previous_floor,
        target_floor_minute: target_floor,
        messages_below_floor: count_messages_below_minute(store, input.workspace_id, target_floor)?,
    })
}

pub fn author_tighten(
    store: &Store,
    input: AuthorTighten,
) -> Result<CommandOutput<AuthorTightenReport>, String> {
    let author_user_id = local_admin_user_id(store, input.workspace_id)?;
    let previous = queries::active_for_workspace(store, input.workspace_id)?;
    let previous_setting_id = previous.as_ref().map(|row| row.setting_id);
    let previous_floor = previous.as_ref().map(|row| row.retire_minute).unwrap_or(0);
    let now_minute = input.now_ms / UNIX_MINUTE_MS;
    let target_floor = now_minute.saturating_sub(u64::from(input.ttl_minutes));
    if target_floor < previous_floor {
        return Err(
            "disappearing setting floor must be monotonic non-decreasing (current floor \
             already exceeds now_minute - new_ttl_minutes; use disappearing-set instead)"
                .to_string(),
        );
    }
    let fact = setting_fact(
        input.workspace_id,
        previous_setting_id,
        input.ttl_minutes,
        target_floor,
        author_user_id,
        input.now_ms,
    )?;
    Ok(CommandOutput::new(AuthorTightenReport {
        setting_fact_id: fact.id,
        previous_floor_minute: previous_floor,
        target_floor_minute: target_floor,
    })
    .with_facts(vec![fact]))
}

pub fn author_compact(
    store: &Store,
    input: AuthorCompact,
) -> Result<CommandOutput<AuthorCompactReport>, String> {
    let active = queries::active_for_workspace(store, input.workspace_id)?.ok_or_else(|| {
        "no active disappearing-messages setting; use disappearing-set first".to_string()
    })?;
    let author_user_id = local_admin_user_id(store, input.workspace_id)?;
    let now_minute = input.now_ms / UNIX_MINUTE_MS;
    let target_floor = active
        .retire_minute
        .max(now_minute.saturating_sub(u64::from(active.ttl_minutes)));
    let fact = setting_fact(
        input.workspace_id,
        Some(active.setting_id),
        active.ttl_minutes,
        target_floor,
        author_user_id,
        input.now_ms,
    )?;
    Ok(CommandOutput::new(AuthorCompactReport {
        setting_fact_id: fact.id,
        ttl_minutes: active.ttl_minutes,
        previous_floor_minute: active.retire_minute,
        new_floor_minute: target_floor,
    })
    .with_facts(vec![fact]))
}

pub fn count_messages_below_minute(
    store: &Store,
    workspace_id: FactId,
    floor_minute: u64,
) -> Result<usize, String> {
    let rows = store
        .table_rows_with_key_prefix(
            content::sealed_message::rows::SEALED_MESSAGE_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("read sealed message rows: {err}"))?;
    let mut count = 0usize;
    for (key, value) in rows {
        let row = content::sealed_message::rows::decode_sealed_message_row(&key, &value)?;
        if row.minute < floor_minute {
            count += 1;
        }
    }
    Ok(count)
}

fn setting_fact(
    workspace_id: FactId,
    supersedes_setting_id: Option<FactId>,
    ttl_minutes: u32,
    retire_minute: u64,
    author_user_id: FactId,
    created_at_ms: u64,
) -> Result<Fact, String> {
    let payload = DisappearingMessagesSettingFact {
        workspace_id,
        supersedes_setting_id,
        ttl_minutes,
        retire_minute,
        scope_kind: SCOPE_KIND_WORKSPACE,
        scope_id: workspace_id,
        author_user_id,
        created_at_ms,
    };
    Ok(Fact::new(
        FactScope::Global,
        created_at_ms,
        layout::encode_fact(&payload)?,
    ))
}

fn local_admin_user_id(store: &Store, workspace_id: FactId) -> Result<FactId, String> {
    let membership = identity::workspace::local_membership::local_membership(store, workspace_id)?
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    let user_id = membership.user_authority_fact_id;
    let admin_rows = store
        .table_rows_with_key_prefix(identity::admin::rows::ADMIN_ROWS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load admin rows: {err}"))?;
    let is_admin = admin_rows.into_iter().any(|(key, value)| {
        identity::admin::rows::decode_admin_row(&key, &value)
            .map(|row| row.user_fact_id == user_id)
            .unwrap_or(false)
    });
    if !is_admin {
        return Err("local user is not an admin in this workspace".to_string());
    }
    Ok(user_id)
}
