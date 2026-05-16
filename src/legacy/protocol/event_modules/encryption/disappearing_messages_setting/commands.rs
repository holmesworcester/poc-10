//! Commands for emitting `disappearing_messages_setting` events.
//!
//! The setting is signed by the authority admin (`authority_admin_event_id`)
//! and wrapped in this module's own signed envelope. The projector validates
//! that the envelope's signer matches the inner authority admin and that
//! the admin's public key matches the envelope's signer key.
//!
//! Slice 5 adds the monotonic floor field. The command takes the current
//! active setting (if any) so the new event names its predecessor in
//! canonical bytes; the projector validates the floor is non-decreasing
//! against that predecessor's canonical bytes (delivered as a dependency).

use crate::core::crypto::Ed25519PrivateKey;
use crate::core::store::Store;
use crate::legacy::protocol::event_modules::content::message::types::UNIX_MINUTE_MS;
use crate::legacy::protocol::event_modules::identity::{admin, endpoint, endpoint_shared};
use crate::legacy::protocol::event_modules::types::{event_id, EventId};
use crate::legacy::protocol::event_modules::worker::{CommandOutput, ProposedEvent};

use super::layout;
use super::queries as setting_queries;
use super::types::DisappearingMessagesSettingEvent;

/// Sanity guard: `effective_at_minute` must equal `created_at_ms / 60_000`.
/// The layout is intentionally lenient on decode; this helper is shared
/// between the authoring path and the receive projector so a malformed
/// peer event is rejected at projection time too.
pub(super) fn validate_event_fields(
    event: &DisappearingMessagesSettingEvent,
) -> Result<(), String> {
    let expected = event.created_at_ms / 60_000;
    if event.effective_at_minute != expected {
        return Err(
            "disappearing_messages_setting effective_at_minute disagrees with created_at_ms"
                .to_string(),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetDisappearingMessages {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub ttl_minutes: u32,
    pub authority_admin_event_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    /// Monotonic deletion floor for this setting. Must be >= the
    /// active setting's floor (validated by the projector).
    pub expires_at_or_before_minute: u64,
    /// Predecessor active-setting id, if any. The projector requires this
    /// dependency be present so it can validate the floor non-decrease;
    /// `None` is only legal when no setting has yet been admitted for the
    /// workspace.
    pub previous_setting_id: Option<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetDisappearingMessagesOutput {
    pub setting_event_id: EventId,
    pub inner_setting_id: EventId,
}

pub fn set(
    input: SetDisappearingMessages,
) -> Result<CommandOutput<SetDisappearingMessagesOutput>, String> {
    let inner = DisappearingMessagesSettingEvent {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        ttl_minutes: input.ttl_minutes,
        authority_admin_event_id: input.authority_admin_event_id,
        effective_at_minute: input.created_at_ms / 60_000,
        expires_at_or_before_minute: input.expires_at_or_before_minute,
        previous_setting_id: input.previous_setting_id,
    };
    validate_event_fields(&inner)?;
    let payload = layout::encode(&inner);
    let inner_setting_id = event_id(&payload);
    let envelope = layout::sign(
        input.authority_admin_event_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = layout::encode_signed(&envelope);
    let record = layout::signed_record_from_bytes(bytes)?;
    let setting_event_id = event_id(&record.canonical_bytes);
    let proposed = ProposedEvent::new(record);
    Ok(CommandOutput::with_proposed_events(
        SetDisappearingMessagesOutput {
            setting_event_id,
            inner_setting_id,
        },
        vec![proposed],
    ))
}

// ---------------------------------------------------------------------------
// CLI-driven authoring helpers
// ---------------------------------------------------------------------------
//
// These functions absorb the multi-step state reads and floor-management
// logic that previously lived in `encryption/cli.rs`. They read the store
// for predecessor settings and authority/admin material, compute the new
// floor under the documented rules, and call `set` to produce the signed
// event. The CLI runners are now thin wrappers that parse argv, call one
// of these helpers, admit the resulting events, and format the report.

/// Inputs the CLI knows about when authoring a `disappearing-set`.
/// `explicit_floor` is `Some` only when the operator passed `--floor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorSetting {
    pub workspace_id: EventId,
    /// Current authoring timestamp (already advanced past the workspace
    /// max). Used both for the event's `created_at_ms` and for computing
    /// the auto-floor `now_minute - ttl_minutes`.
    pub now_ms: u64,
    pub ttl_minutes: u32,
    /// `Some(minute)` when the operator passed `--floor MINUTE`. Below the
    /// previous floor is rejected before any event is constructed.
    pub explicit_floor: Option<u64>,
}

/// Report returned by `author_set_with_auto_floor`. The CLI uses these
/// fields to render its output lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorSetReport {
    pub setting_event_id: EventId,
    pub previous_floor_minute: u64,
    pub new_floor_minute: u64,
}

/// Compose `disappearing-set`: resolve workspace authority/admin material,
/// look up the previous active setting, compute the new floor under the
/// documented rule (`max(previous_floor, now_minute - ttl_minutes)` by
/// default, `--floor` explicit override rejected below the previous
/// floor), and sign the resulting event.
pub fn author_set_with_auto_floor(
    store: &Store,
    input: AuthorSetting,
) -> Result<CommandOutput<AuthorSetReport>, String> {
    let auth = resolve_workspace_authority(store, input.workspace_id)?;
    let previous = setting_queries::active_for_workspace(store, input.workspace_id)?;
    let previous_setting_id = previous.as_ref().map(|row| row.setting_event_id);
    let previous_floor = previous
        .as_ref()
        .map(|row| row.expires_at_or_before_minute)
        .unwrap_or(0);

    let now_minute = input.now_ms / UNIX_MINUTE_MS;
    // Default behavior: every set is also a floor-advance opportunity
    // (loosenings naturally GC subsumed debris). Pin the new floor to
    // max(previous_floor, now_minute - new_ttl_minutes) so a setting
    // with a longer TTL stays at or above the previous floor, and a
    // setting with the same or shorter TTL monotonically advances it.
    let auto_floor = std::cmp::max(
        previous_floor,
        now_minute.saturating_sub(u64::from(input.ttl_minutes)),
    );
    let new_floor = match input.explicit_floor {
        Some(value) => {
            if value < previous_floor {
                // Mirror the projector's error so an operator who tries
                // to regress the floor sees the same wording end-to-end.
                // Bail out *before* admitting the event so the failed
                // call has no on-disk side effect.
                return Err(
                    "disappearing setting floor must be monotonic non-decreasing".to_string(),
                );
            }
            value
        }
        None => auto_floor,
    };
    let inner = set(SetDisappearingMessages {
        workspace_id: input.workspace_id,
        created_at_ms: input.now_ms,
        ttl_minutes: input.ttl_minutes,
        authority_admin_event_id: auth.admin_id,
        signer_private_key: auth.signing_secret,
        expires_at_or_before_minute: new_floor,
        previous_setting_id,
    })?;
    Ok(CommandOutput::with_proposed_events(
        AuthorSetReport {
            setting_event_id: inner.value.setting_event_id,
            previous_floor_minute: previous_floor,
            new_floor_minute: new_floor,
        },
        inner.events,
    ))
}

/// Inputs the CLI knows about when authoring a `disappearing-tighten`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorTighten {
    pub workspace_id: EventId,
    pub now_ms: u64,
    pub ttl_minutes: u32,
}

/// Report from `author_tighten`. The CLI surfaces these in its output and
/// uses `messages_below_floor` for the confirmation prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorTightenReport {
    pub setting_event_id: EventId,
    pub previous_floor_minute: u64,
    pub target_floor_minute: u64,
}

/// Plan a `disappearing-tighten` without authoring yet. Returns the
/// target floor + previous floor + an estimate of messages that will
/// fall below the new floor. The CLI uses this for the operator
/// confirmation prompt; after the operator confirms, it calls
/// `author_tighten` with the same inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TightenPlan {
    pub previous_floor_minute: u64,
    pub target_floor_minute: u64,
    pub messages_below_floor: usize,
}

pub fn plan_tighten(store: &Store, input: AuthorTighten) -> Result<TightenPlan, String> {
    let _auth = resolve_workspace_authority(store, input.workspace_id)?;
    let previous = setting_queries::active_for_workspace(store, input.workspace_id)?;
    let previous_floor = previous
        .as_ref()
        .map(|row| row.expires_at_or_before_minute)
        .unwrap_or(0);
    let now_minute = input.now_ms / UNIX_MINUTE_MS;
    let target_floor = now_minute.saturating_sub(u64::from(input.ttl_minutes));
    if target_floor < previous_floor {
        return Err(
            "disappearing setting floor must be monotonic non-decreasing (current floor \
             already exceeds now_minute - new_ttl_minutes; use disappearing-set instead)"
                .to_string(),
        );
    }
    let messages_below_floor =
        count_messages_below_minute(store, input.workspace_id, target_floor)?;
    Ok(TightenPlan {
        previous_floor_minute: previous_floor,
        target_floor_minute: target_floor,
        messages_below_floor,
    })
}

/// Author the tighten event. Must be called after `plan_tighten` returned
/// `Ok(_)` for the same inputs; `plan_tighten`'s monotonicity guard is
/// re-applied here so a bypassed prompt cannot regress the floor.
pub fn author_tighten(
    store: &Store,
    input: AuthorTighten,
) -> Result<CommandOutput<AuthorTightenReport>, String> {
    let auth = resolve_workspace_authority(store, input.workspace_id)?;
    let previous = setting_queries::active_for_workspace(store, input.workspace_id)?;
    let previous_setting_id = previous.as_ref().map(|row| row.setting_event_id);
    let previous_floor = previous
        .as_ref()
        .map(|row| row.expires_at_or_before_minute)
        .unwrap_or(0);
    let now_minute = input.now_ms / UNIX_MINUTE_MS;
    let target_floor = now_minute.saturating_sub(u64::from(input.ttl_minutes));
    if target_floor < previous_floor {
        return Err(
            "disappearing setting floor must be monotonic non-decreasing (current floor \
             already exceeds now_minute - new_ttl_minutes; use disappearing-set instead)"
                .to_string(),
        );
    }
    let inner = set(SetDisappearingMessages {
        workspace_id: input.workspace_id,
        created_at_ms: input.now_ms,
        ttl_minutes: input.ttl_minutes,
        authority_admin_event_id: auth.admin_id,
        signer_private_key: auth.signing_secret,
        expires_at_or_before_minute: target_floor,
        previous_setting_id,
    })?;
    Ok(CommandOutput::with_proposed_events(
        AuthorTightenReport {
            setting_event_id: inner.value.setting_event_id,
            previous_floor_minute: previous_floor,
            target_floor_minute: target_floor,
        },
        inner.events,
    ))
}

/// Inputs the CLI knows about when authoring a `disappearing-compact`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorCompact {
    pub workspace_id: EventId,
    pub now_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorCompactReport {
    pub setting_event_id: EventId,
    pub ttl_minutes: u32,
    pub previous_floor_minute: u64,
    pub new_floor_minute: u64,
}

/// Compose `disappearing-compact`: re-author the active setting with the
/// same TTL but advance the floor to `max(previous_floor, now_minute -
/// current_ttl_minutes)`. This is the no-live-message-deletion floor: by
/// construction every live message stamped under the current policy has
/// `expires_at_minute >= new_floor`, so only debris below the floor is
/// collected.
pub fn author_compact(
    store: &Store,
    input: AuthorCompact,
) -> Result<CommandOutput<AuthorCompactReport>, String> {
    let auth = resolve_workspace_authority(store, input.workspace_id)?;
    let active =
        setting_queries::active_for_workspace(store, input.workspace_id)?.ok_or_else(|| {
            "no active disappearing-messages setting; use disappearing-set first".to_string()
        })?;
    let previous_floor = active.expires_at_or_before_minute;
    let ttl_minutes = active.ttl_minutes;
    let now_minute = input.now_ms / UNIX_MINUTE_MS;
    let target_floor = std::cmp::max(
        previous_floor,
        now_minute.saturating_sub(u64::from(ttl_minutes)),
    );
    let inner = set(SetDisappearingMessages {
        workspace_id: input.workspace_id,
        created_at_ms: input.now_ms,
        ttl_minutes,
        authority_admin_event_id: auth.admin_id,
        signer_private_key: auth.signing_secret,
        expires_at_or_before_minute: target_floor,
        previous_setting_id: Some(active.setting_event_id),
    })?;
    Ok(CommandOutput::with_proposed_events(
        AuthorCompactReport {
            setting_event_id: inner.value.setting_event_id,
            ttl_minutes,
            previous_floor_minute: previous_floor,
            new_floor_minute: target_floor,
        },
        inner.events,
    ))
}

/// Resolved workspace authority: local endpoint membership + the admin id
/// that authorizes settings for the local user.
struct WorkspaceAuthority {
    admin_id: EventId,
    signing_secret: Ed25519PrivateKey,
}

fn resolve_workspace_authority(
    store: &Store,
    workspace_id: EventId,
) -> Result<WorkspaceAuthority, String> {
    let membership = require_local_membership(store, workspace_id)?;
    let local = endpoint::commands::local_keypair(store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let admin_id = admin_for_user(store, workspace_id, membership.user_authority_event_id)?
        .ok_or_else(|| "local user is not an admin in this workspace".to_string())?;
    Ok(WorkspaceAuthority {
        admin_id,
        signing_secret: local.signing_secret,
    })
}

fn require_local_membership(
    store: &Store,
    workspace_id: EventId,
) -> Result<endpoint_shared::types::EndpointMembershipRow, String> {
    let local = endpoint::commands::local_keypair(store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let key = endpoint_shared::rows::endpoint_membership_key(local.endpoint, workspace_id);
    let value = store
        .table_row(endpoint_shared::rows::ENDPOINT_MEMBERSHIPS, &key)
        .map_err(|err| format!("load endpoint membership: {err}"))?
        .ok_or_else(|| "local endpoint is not joined to workspace".to_string())?;
    let row = endpoint_shared::rows::decode_endpoint_membership_row(&key, &value)?;
    if row.signing_public_key != local.signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }
    Ok(row)
}

fn admin_for_user(
    store: &Store,
    workspace_id: EventId,
    user_id: EventId,
) -> Result<Option<EventId>, String> {
    for (key, value) in store
        .table_rows_with_key_prefix(admin::rows::ADMINS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load admins: {err}"))?
    {
        let row = admin::rows::decode_admin_row(&key, &value)?;
        if row.user_event_id == user_id {
            return Ok(Some(row.admin_id));
        }
    }
    Ok(None)
}

/// Count live (opened + still-sealed) messages whose authoring minute is
/// strictly below `floor_minute`. Used by `plan_tighten` to surface a hint
/// in the operator confirmation prompt.
fn count_messages_below_minute(
    store: &Store,
    workspace_id: EventId,
    floor_minute: u64,
) -> Result<usize, String> {
    use crate::legacy::protocol::event_modules::content::message::queries as message_queries;
    let mut count = 0usize;
    for row in message_queries::list_for_workspace(store, workspace_id)? {
        if row.created_at_ms / UNIX_MINUTE_MS < floor_minute {
            count += 1;
        }
    }
    for row in message_queries::list_sealed_for_workspace(store, workspace_id)? {
        if row.created_at_ms / UNIX_MINUTE_MS < floor_minute {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::legacy::protocol::event_modules::types::EventScope;

    use super::*;

    #[test]
    fn set_proposes_signed_setting_event_with_admin_dep() {
        let signer_private_key = [9; crypto::ED25519_PRIVATE_KEY_BYTES];
        let output = set(SetDisappearingMessages {
            workspace_id: [1; 32],
            created_at_ms: 6_000_000,
            ttl_minutes: 5,
            authority_admin_event_id: [2; 32],
            signer_private_key,
            expires_at_or_before_minute: 0,
            previous_setting_id: None,
        })
        .expect("set");
        assert_eq!(output.events.len(), 1);
        let record = output.events[0].record();
        assert_eq!(record.timestamp, 6_000_000);
        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.dependencies, vec![[2; 32], [1; 32]]);
    }

    #[test]
    fn deterministic_event_id_from_canonical_bytes() {
        let signer_private_key = [9; crypto::ED25519_PRIVATE_KEY_BYTES];
        let input = SetDisappearingMessages {
            workspace_id: [1; 32],
            created_at_ms: 6_000_000,
            ttl_minutes: 5,
            authority_admin_event_id: [2; 32],
            signer_private_key,
            expires_at_or_before_minute: 0,
            previous_setting_id: None,
        };
        let first = set(input.clone()).expect("first");
        let second = set(input).expect("second");
        assert_eq!(first.events[0].event_id(), second.events[0].event_id());
    }

    #[test]
    fn set_includes_previous_setting_as_dependency_when_present() {
        let signer_private_key = [9; crypto::ED25519_PRIVATE_KEY_BYTES];
        let output = set(SetDisappearingMessages {
            workspace_id: [1; 32],
            created_at_ms: 6_000_000,
            ttl_minutes: 5,
            authority_admin_event_id: [2; 32],
            signer_private_key,
            expires_at_or_before_minute: 50,
            previous_setting_id: Some([42; 32]),
        })
        .expect("set");
        let record = output.events[0].record();
        assert_eq!(record.dependencies, vec![[2; 32], [1; 32], [42; 32]]);
    }
}
