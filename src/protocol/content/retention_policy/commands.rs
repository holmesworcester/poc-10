//! Command-facing retention policy constructors.
//!
//! These helpers read projected state, compute the monotonic floor, and return
//! a proposed retention policy fact. Projection and purge execution stay in the
//! target runtime.

use crate::core::clock;
use crate::core::command::CommandOutput;
use crate::core::crypto::{self, Ed25519PrivateKey, Ed25519PublicKey};
use crate::core::facts::FactId;
use crate::core::store::Store;
use crate::protocol::auth::signature::author::AuthoredFactEvidence;
use crate::protocol::{auth, content};
use std::collections::BTreeSet;

use super::fact::SCOPE_KIND_WORKSPACE;
use super::{author, queries};

pub const UNIX_MINUTE_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorPolicy {
    pub workspace_id: FactId,
    pub now_ms: u64,
    pub ttl_minutes: u32,
    pub explicit_floor: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorSetReport {
    pub policy_fact_id: FactId,
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
    pub policy_fact_id: FactId,
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
    pub policy_fact_id: FactId,
    pub ttl_minutes: u32,
    pub previous_floor_minute: u64,
    pub new_floor_minute: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusReport {
    pub workspace_id: FactId,
    pub policy_fact_id: Option<FactId>,
    pub ttl_minutes: Option<u32>,
    pub policy_floor_minute: u64,
    pub last_chopped_floor: Option<u64>,
    pub now_minute: Option<u64>,
    pub horizon_floor: u64,
    pub effective_floor: u64,
    pub live_messages: usize,
    pub message_tombstones: usize,
}

pub fn author_set_with_auto_floor(
    store: &Store,
    input: AuthorPolicy,
) -> Result<CommandOutput<AuthorSetReport>, String> {
    if input.ttl_minutes == 0 {
        return Err("retention policy ttl_minutes must be non-zero".to_string());
    }
    let author_user_id = local_admin_user_id(store, input.workspace_id)?;
    let previous = queries::active_for_workspace(store, input.workspace_id)?;
    let previous_policy_id = previous.as_ref().map(|row| row.policy_id);
    let previous_floor = previous.as_ref().map(|row| row.retire_minute).unwrap_or(0);
    let now_minute = input.now_ms / UNIX_MINUTE_MS;
    let auto_floor = previous_floor.max(now_minute.saturating_sub(u64::from(input.ttl_minutes)));
    let new_floor = match input.explicit_floor {
        Some(floor) if floor < previous_floor => {
            return Err("retention policy floor must be monotonic non-decreasing".to_string());
        }
        Some(floor) => floor,
        None => auto_floor,
    };

    let authored = policy_fact(
        store,
        input.workspace_id,
        previous_policy_id,
        input.ttl_minutes,
        new_floor,
        author_user_id,
        input.now_ms,
    )?;
    Ok(CommandOutput::new(AuthorSetReport {
        policy_fact_id: authored.fact.id,
        previous_floor_minute: previous_floor,
        new_floor_minute: new_floor,
    })
    .with_facts(authored.into_facts().to_vec()))
}

pub fn plan_tighten(store: &Store, input: AuthorTighten) -> Result<TightenPlan, String> {
    if input.ttl_minutes == 0 {
        return Err("retention policy ttl_minutes must be non-zero".to_string());
    }
    let _author_user_id = local_admin_user_id(store, input.workspace_id)?;
    let previous = queries::active_for_workspace(store, input.workspace_id)?;
    let previous_floor = previous.as_ref().map(|row| row.retire_minute).unwrap_or(0);
    let now_minute = input.now_ms / UNIX_MINUTE_MS;
    let target_floor = now_minute.saturating_sub(u64::from(input.ttl_minutes));
    if target_floor < previous_floor {
        return Err(
            "retention policy floor must be monotonic non-decreasing (current floor \
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
    let previous_policy_id = previous.as_ref().map(|row| row.policy_id);
    let previous_floor = previous.as_ref().map(|row| row.retire_minute).unwrap_or(0);
    let now_minute = input.now_ms / UNIX_MINUTE_MS;
    let target_floor = now_minute.saturating_sub(u64::from(input.ttl_minutes));
    if target_floor < previous_floor {
        return Err(
            "retention policy floor must be monotonic non-decreasing (current floor \
             already exceeds now_minute - new_ttl_minutes; use disappearing-set instead)"
                .to_string(),
        );
    }
    let authored = policy_fact(
        store,
        input.workspace_id,
        previous_policy_id,
        input.ttl_minutes,
        target_floor,
        author_user_id,
        input.now_ms,
    )?;
    Ok(CommandOutput::new(AuthorTightenReport {
        policy_fact_id: authored.fact.id,
        previous_floor_minute: previous_floor,
        target_floor_minute: target_floor,
    })
    .with_facts(authored.into_facts().to_vec()))
}

pub fn author_compact(
    store: &Store,
    input: AuthorCompact,
) -> Result<CommandOutput<AuthorCompactReport>, String> {
    let active = queries::active_for_workspace(store, input.workspace_id)?
        .ok_or_else(|| "no active retention policy; use disappearing-set first".to_string())?;
    let author_user_id = local_admin_user_id(store, input.workspace_id)?;
    let now_minute = input.now_ms / UNIX_MINUTE_MS;
    let target_floor = active
        .retire_minute
        .max(now_minute.saturating_sub(u64::from(active.ttl_minutes)));
    let authored = policy_fact(
        store,
        input.workspace_id,
        Some(active.policy_id),
        active.ttl_minutes,
        target_floor,
        author_user_id,
        input.now_ms,
    )?;
    Ok(CommandOutput::new(AuthorCompactReport {
        policy_fact_id: authored.fact.id,
        ttl_minutes: active.ttl_minutes,
        previous_floor_minute: active.retire_minute,
        new_floor_minute: target_floor,
    })
    .with_facts(authored.into_facts().to_vec()))
}

pub fn count_messages_below_minute(
    store: &Store,
    workspace_id: FactId,
    floor_minute: u64,
) -> Result<usize, String> {
    let mut message_ids = BTreeSet::new();

    for row in content::message::queries::content_message_rows(store, workspace_id)? {
        if row.minute < floor_minute {
            message_ids.insert(row.message_id);
        }
    }
    for message_id in
        content::message::queries::message_tombstone_ids_below(store, workspace_id, floor_minute)?
    {
        message_ids.insert(message_id);
    }

    Ok(message_ids.len())
}

pub fn status_report(store: &Store, workspace_id: FactId) -> Result<StatusReport, String> {
    let active = queries::active_for_workspace(store, workspace_id)?;
    let policy_fact_id = active.as_ref().map(|row| row.policy_id);
    let ttl_minutes = active.as_ref().map(|row| row.ttl_minutes);
    let policy_floor_minute = active.as_ref().map(|row| row.retire_minute).unwrap_or(0);
    let now_minute = clock::logical_time(store)?.map(|ms| ms / UNIX_MINUTE_MS);
    let horizon_floor = now_minute
        .map(|minute| minute.saturating_sub(30 * 24 * 60))
        .unwrap_or(0);
    let effective_floor = policy_floor_minute.max(horizon_floor);
    let message_tombstones = content::message::queries::message_tombstone_count_at_or_after(
        store,
        workspace_id,
        horizon_floor,
    )?;
    let live_messages = content::message::queries::content_message_rows(store, workspace_id)?
        .into_iter()
        .filter(|row| row.minute >= horizon_floor)
        .count();
    let last_chopped_floor =
        (horizon_floor > policy_floor_minute && horizon_floor > 0).then_some(horizon_floor);

    Ok(StatusReport {
        workspace_id,
        policy_fact_id,
        ttl_minutes,
        policy_floor_minute,
        last_chopped_floor,
        now_minute,
        horizon_floor,
        effective_floor,
        live_messages,
        message_tombstones,
    })
}

fn policy_fact(
    store: &Store,
    workspace_id: FactId,
    supersedes_policy_id: Option<FactId>,
    ttl_minutes: u32,
    retire_minute: u64,
    author_user_id: FactId,
    created_at_ms: u64,
) -> Result<AuthoredFactEvidence, String> {
    let (signer_id, _signer_public_key, signer_private_key) =
        local_signing_material(store, workspace_id)?;
    let fact = author::authored_retention_policy_fact(
        workspace_id,
        supersedes_policy_id,
        ttl_minutes,
        retire_minute,
        SCOPE_KIND_WORKSPACE,
        workspace_id,
        author_user_id,
        signer_id,
        created_at_ms,
        signer_private_key,
    )?;
    let signature = auth::signature::author::sign_fact(
        workspace_id,
        &fact,
        &signer_private_key,
        created_at_ms,
    )?;
    Ok(AuthoredFactEvidence { fact, signature })
}

fn local_signing_material(
    store: &Store,
    workspace_id: FactId,
) -> Result<(FactId, Ed25519PublicKey, Ed25519PrivateKey), String> {
    auth::workspace::queries::local_membership(store, workspace_id)?
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    let endpoint_id = local_endpoint_field(
        store,
        auth::endpoint::LOCAL_ENDPOINT_ROWS,
        "local endpoint id",
    )?;
    let public_key = local_endpoint_field(
        store,
        auth::endpoint::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
        "local endpoint signing public key",
    )?;
    let private_key = local_endpoint_field(
        store,
        auth::endpoint::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS,
        "local endpoint signing secret",
    )?;
    if crypto::ed25519_public_key(&private_key) != public_key {
        return Err("local endpoint signing public key does not match secret".to_string());
    }
    Ok((endpoint_id, public_key, private_key))
}

fn local_endpoint_field(
    store: &Store,
    table: crate::core::store::TableName,
    label: &str,
) -> Result<[u8; 32], String> {
    let value = store
        .table_row(table, auth::endpoint::LOCAL_KEY)
        .map_err(|err| format!("load {label}: {err}"))?
        .ok_or_else(|| format!("{label} is missing"))?;
    value
        .try_into()
        .map_err(|_| format!("{label} row must be 32 bytes"))
}

fn local_admin_user_id(store: &Store, workspace_id: FactId) -> Result<FactId, String> {
    let membership = auth::workspace::queries::local_membership(store, workspace_id)?
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    let user_id = membership.user_authority_fact_id;
    let admin_rows = store
        .table_rows_with_key_prefix(auth::admin::ADMIN_ROWS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load admin rows: {err}"))?;
    let is_admin = admin_rows.into_iter().any(|(key, value)| {
        auth::admin::queries::decode_admin_row(&key, &value)
            .map(|row| row.user_fact_id == user_id)
            .unwrap_or(false)
    });
    if !is_admin {
        return Err("local user is not an admin in this workspace".to_string());
    }
    Ok(user_id)
}
