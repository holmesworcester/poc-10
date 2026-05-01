//! Decrypt-and-recurse handling for `ParsedEvent::Encrypted`.
//!
//! `apply_encrypted` is dispatched from [`super::dispatch::project_and_apply`]
//! whenever the parsed event is `ParsedEvent::Encrypted`. It resolves the
//! workspace key, AES-256-GCM decrypts the ciphertext, and re-enters the
//! per-inner-event chain on the recovered canonical bytes via
//! [`project_inner_decrypted`]. The outer encrypted row's
//! `events_canonical` status is mirrored from the inner disposition so
//! the wrapper never advertises Applied while the inner is still in
//! flight or has failed.

use rusqlite::Connection;

use crate::event_modules::encrypted::{decrypt_encrypted, DecryptOutcome};
use crate::event_modules::{parse_event, ParsedEvent};
use crate::state::admission::{admit_event_id, AdmissionResult};
use crate::state::events_canonical::{
    add_blockers, finalize_admitted, set_status, unblock_dependents, EventScope, EventStatus,
};

use super::super::work_item::{BlakeId, WorkspaceId};
use super::dispatch::project_and_apply;
use super::sync_maintenance::apply_sync_maintenance;
use super::{ChainError, InnerEventDisposition};

/// Decrypt-and-recurse handling for `ParsedEvent::Encrypted`.
///
/// Resolves the workspace key (in the same db transaction the chain
/// already holds), AES-256-GCM decrypts the ciphertext, then re-enters
/// the per-inner-event chain (admit_event_id → parse → finalize →
/// project_and_apply) on the recovered canonical bytes.
///
/// Disposition rules for the OUTER encrypted event mirror the INNER
/// disposition. The outer encrypted row's `events_canonical` status is
/// kept in sync with the reported disposition so durability reflects
/// what the wire payload actually achieved:
///   - Inner `Applied` → outer `Applied`; outer's dependents are
///     unblocked. Inner has its own `events_canonical` row carrying its
///     own status.
///   - Inner `Blocked { missing }` → outer `Blocked` with the SAME
///     `missing_deps`. Outer cannot be considered applied until its
///     inner can be applied. `add_blockers` writes the dep edges (or
///     `set_status(Blocked)` is used directly when missing is empty —
///     a guard-block scenario, e.g. workspace projector pre-binding).
///   - Inner `Rejected { reason }` → outer `Rejected` with reason
///     prefixed by `inner-rejected:` so callers can distinguish wrapper
///     vs. inner failures.
///   - Inner `ParseFailed { error }` → outer `Rejected` with reason
///     prefixed by `inner parse failed:`. The OUTER parsed fine — only
///     the recovered plaintext was unparseable — so `Rejected` is the
///     accurate disposition for the wrapper.
///   - Inner `AlreadyKnown { status }` → outer mirrors. If we've seen
///     the inner before with a terminal status, the outer carries that
///     verdict. Outer is marked `Applied` only when the previously seen
///     inner was itself `Applied`.
///   - Workspace key not yet locally present → outer marked `Blocked`
///     on the missing `key_event_id`. The chain returns
///     `InnerEventDisposition::Blocked { missing_deps: vec![key_id] }`.
///     When the key arrives later, the standard `unblock_dependents`
///     pathway flips the encrypted row to `ready`, and the
///     `ReadyEvent` handler re-attempts decrypt.
///   - Inner ciphertext fails AEAD verify, or recovered plaintext is
///     itself an encrypted event (forbidden — encrypted events do not
///     nest), or inner type_code disagrees with declared
///     `inner_type_code` → outer marked `Rejected`.
pub(super) fn apply_encrypted(
    db: &Connection,
    outer_event_id: &BlakeId,
    ev: &crate::event_modules::EncryptedEvent,
    workspace_id: Option<WorkspaceId>,
) -> Result<InnerEventDisposition, ChainError> {
    // Fail closed: encrypted events never wrap encrypted events.
    if ev.inner_type_code == crate::event_modules::EVENT_TYPE_ENCRYPTED {
        let reason = "nested encryption not allowed".to_string();
        set_status(db, outer_event_id, EventStatus::Rejected).map_err(ChainError::Db)?;
        return Ok(InnerEventDisposition::Rejected { reason });
    }

    // 1. Resolve key + AEAD verify.
    let outcome = decrypt_encrypted(ev, db).map_err(ChainError::Db)?;
    let inner = match outcome {
        DecryptOutcome::Decrypted(d) => d,
        DecryptOutcome::KeyMissing { key_id } => {
            // Block the encrypted event on the missing workspace key.
            // `add_blockers` writes the (key_id, outer_event_id) edge
            // and flips outer to `blocked` (events_canonical lifecycle).
            add_blockers(db, outer_event_id, &[key_id]).map_err(ChainError::Db)?;
            return Ok(InnerEventDisposition::Blocked {
                missing_deps: vec![key_id],
            });
        }
        DecryptOutcome::InvalidCiphertext { reason } => {
            set_status(db, outer_event_id, EventStatus::Rejected).map_err(ChainError::Db)?;
            return Ok(InnerEventDisposition::Rejected { reason });
        }
    };

    // 2. Type-code consistency check: declared inner_type_code must
    //    match the recovered plaintext's first byte (the type byte).
    let inner_first = inner.canonical_bytes.first().copied().unwrap_or(0);
    if inner_first != ev.inner_type_code {
        let reason = format!(
            "inner type mismatch: outer declares {}, plaintext is {}",
            ev.inner_type_code, inner_first
        );
        set_status(db, outer_event_id, EventStatus::Rejected).map_err(ChainError::Db)?;
        return Ok(InnerEventDisposition::Rejected { reason });
    }

    // 3. Recurse: run the per-inner chain on the recovered bytes —
    //    admit_event_id → parse → finalize_admitted → project_and_apply.
    //    The inner event_id is BLAKE3 of plaintext (control_loop convention).
    let inner_disposition = project_inner_decrypted(
        db,
        &inner.canonical_bytes,
        &inner.event_id,
        workspace_id,
    )?;

    // 4. Mirror the inner disposition onto the outer encrypted event's
    //    `events_canonical` row and surface a matching disposition to
    //    the caller. The outer must NEVER be marked `Applied` if its
    //    inner failed or is still waiting — that was the bug Codex
    //    caught.
    let outer_disposition = match &inner_disposition {
        InnerEventDisposition::Applied => {
            set_status(db, outer_event_id, EventStatus::Applied).map_err(ChainError::Db)?;
            // Run unblock_dependents in case anything was waiting on
            // the encrypted event id specifically.
            let _ = unblock_dependents(db, outer_event_id).map_err(ChainError::Db)?;
            // The outer encrypted row is itself durable — run sync
            // maintenance for it too. The inner event already had its
            // maintenance run when project_and_apply transitioned the
            // inner row to Applied.
            apply_sync_maintenance(db, outer_event_id, workspace_id)?;
            InnerEventDisposition::Applied
        }
        InnerEventDisposition::Blocked { missing_deps } => {
            // Outer is blocked on the same deps as inner. `add_blockers`
            // is a no-op for empty `missing_deps`, so flip status
            // directly in that case (guard-block scenario).
            if missing_deps.is_empty() {
                set_status(db, outer_event_id, EventStatus::Blocked)
                    .map_err(ChainError::Db)?;
            } else {
                add_blockers(db, outer_event_id, missing_deps).map_err(ChainError::Db)?;
            }
            InnerEventDisposition::Blocked {
                missing_deps: missing_deps.clone(),
            }
        }
        InnerEventDisposition::Rejected { reason } => {
            set_status(db, outer_event_id, EventStatus::Rejected).map_err(ChainError::Db)?;
            InnerEventDisposition::Rejected {
                reason: format!("inner-rejected: {}", reason),
            }
        }
        InnerEventDisposition::ParseFailed { error } => {
            // Outer parsed fine; the failure is on the recovered plaintext.
            // Surface as Rejected so the outer row reaches a terminal
            // status (we have no `ParseFailed` slot in events_canonical
            // beyond `rejected`).
            set_status(db, outer_event_id, EventStatus::Rejected).map_err(ChainError::Db)?;
            InnerEventDisposition::Rejected {
                reason: format!("inner parse failed: {}", error),
            }
        }
        InnerEventDisposition::AlreadyKnown { status } => {
            // The inner had been processed earlier under its own row.
            // Mirror its terminal status on the outer.
            match status {
                EventStatus::Applied => {
                    set_status(db, outer_event_id, EventStatus::Applied)
                        .map_err(ChainError::Db)?;
                    let _ = unblock_dependents(db, outer_event_id).map_err(ChainError::Db)?;
                    apply_sync_maintenance(db, outer_event_id, workspace_id)?;
                }
                EventStatus::Rejected => {
                    set_status(db, outer_event_id, EventStatus::Rejected)
                        .map_err(ChainError::Db)?;
                }
                EventStatus::Blocked => {
                    set_status(db, outer_event_id, EventStatus::Blocked)
                        .map_err(ChainError::Db)?;
                }
                _ => {
                    // Processing / Ready: leave outer in `processing`;
                    // the inner is still in flight. Caller surfaces
                    // AlreadyKnown to keep parity with inner.
                }
            }
            InnerEventDisposition::AlreadyKnown { status: *status }
        }
    };

    Ok(outer_disposition)
}

/// Re-entry point for an inner event recovered by decrypting an outer
/// `ParsedEvent::Encrypted`. Mirrors `process_inner_event` but operates
/// on plaintext bytes that already passed AEAD verify.
fn project_inner_decrypted(
    db: &Connection,
    inner_bytes: &[u8],
    inner_event_id: &BlakeId,
    workspace_id: Option<WorkspaceId>,
) -> Result<InnerEventDisposition, ChainError> {
    // Step 3a: admission (before parse). Same `admit_event_id` claim as
    // the outer chain step.
    match admit_event_id(db, *inner_event_id, /* now_ms */ 0).map_err(ChainError::Db)? {
        AdmissionResult::Known { status } => {
            return Ok(InnerEventDisposition::AlreadyKnown { status });
        }
        AdmissionResult::NewlyClaimed => {}
    }

    // Step 3b: parse plaintext.
    let parsed = match parse_event(inner_bytes) {
        Ok(p) => p,
        Err(e) => {
            set_status(db, inner_event_id, EventStatus::Rejected).map_err(ChainError::Db)?;
            return Ok(InnerEventDisposition::ParseFailed {
                error: format!("{:?}", e),
            });
        }
    };

    // Defense in depth: refuse to recurse twice. parse_event would have
    // produced ParsedEvent::Encrypted for a nested-encrypted blob, but
    // we already type-checked the declared inner type byte. Belt + braces.
    if matches!(parsed, ParsedEvent::Encrypted(_)) {
        set_status(db, inner_event_id, EventStatus::Rejected).map_err(ChainError::Db)?;
        return Ok(InnerEventDisposition::Rejected {
            reason: "nested encryption not allowed".to_string(),
        });
    }

    // Step 3c: persist canonical bytes for the inner row. The workspace
    // is mirrored from the outer wrapper — encrypted events bind the
    // workspace via the wrap envelope, not the plaintext.
    finalize_admitted(
        db,
        inner_event_id,
        inner_bytes,
        workspace_id,
        EventScope::Durable,
        EventStatus::Processing,
    )
    .map_err(ChainError::Db)?;

    // Step 3d-g: project + apply (+ unblock_dependents on success).
    project_and_apply(db, inner_event_id, &parsed, workspace_id)
}
