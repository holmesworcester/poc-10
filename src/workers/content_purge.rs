//! Content purge worker.
//!
//! Inputs: durable `content.purge_instructions` rows written by deletion
//! projectors plus durable `content.purge_retire_coords` rows the worker
//! itself stamped during a prior purge transaction.
//! State: content read-model rows, durable message tombstone summaries, the
//! protocol event store, and the two-table purge queue.
//! Step: in one purge transaction, drain up to `limit` instructions: for
//! each, decode the target event bytes if present, verify the retained
//! deletion label or tombstone authorizes cleanup, stamp retire
//! coordinates, perform idempotent read-model cleanup, purge canonical
//! bytes, and enqueue any remaining transitional cascade work. If a
//! message/file instruction arrives before target bytes and before retire
//! coords exist, the instruction remains queued instead of being mistaken
//! for crash recovery.
//! After commit, run the retire-leaf step in its own transactions for
//! every kind whose canonical bytes we actually purged in this call, then
//! delete the `purge_retire_coords` row in a small follow-up transaction.
//! A separate fix-up phase at drain entry processes orphan retire_coords
//! rows left behind by a crashed prior tick.
//! Outputs: `content.message_tombstones` rows and row/event deletes inside
//! the purge transaction; the leaf retirement step runs after commit and
//! writes a sibling-tombstone history-node event while purging retired
//! bytes.
//! Consume: purged event rows leave the durable deletion label/tombstone
//! facts behind so semantic deletion survives without keeping ciphertext
//! bytes. Cascaded reactions/files/slices still ride on the same durable
//! queue as transitional cleanup; the long-term direction is for their
//! projectors to emit those purge intents from dependency labels.
//! Failure: one malformed event aborts that worker transaction and will be
//! retried; projectors remain the authority on validity before normal reads.
//! Fairness: `Work::Drain { limit }` bounds one batch of queue instructions.
//! Concurrency: the purge transaction deletes the instruction row in the
//! same tx that purges bytes, so a second concurrent drain in another
//! process sees an empty queue and skips. Retire walks therefore run
//! sequentially within whichever process first claimed the work. The
//! fix-up phase atomically claims orphan retire_coords by deleting the
//! row in a tiny tx, so two processes cannot run retire for the same
//! orphan coord simultaneously.

use crate::core::daemon::{self, StepContext, Worker};
use crate::core::store::{table_error, Store};
use crate::protocol::event_modules::content::{
    file, file_deletion, file_slice, message, message_deletion, reaction,
};
use crate::protocol::event_modules::queries as event_queries;
use crate::protocol::event_modules::types::EventId;
use crate::workers::encryption as encryption_worker;
use crate::workers::pipeline_helpers::event_pipeline::EventRegistry;
use crate::workers::pipeline_helpers::purging;
use crate::workers::DaemonWorkerContext;

use message_deletion::schema::{
    self as message_deletion_schema, purge_instruction_key, purge_instruction_row,
    purge_retire_coords_row, PurgeInstruction, PurgeKind, PurgeRetireCoords,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub scanned_events: usize,
    pub tombstones_written: usize,
    pub message_rows_deleted: usize,
    pub reaction_rows_deleted: usize,
    pub file_rows_deleted: usize,
    pub file_slice_rows_deleted: usize,
    pub event_bytes_purged: usize,
    pub retired_message_leaves: usize,
}

pub fn run<R: EventRegistry>(
    store: &Store,
    registry: &R,
    work: Work,
) -> Result<PurgeReport, String> {
    match work {
        Work::Drain { limit } => drain(store, registry, limit),
    }
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "content_purge",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    daemon::run_step(
        ctx,
        "purge content",
        |app, limit| run(app.store(), app, Work::Drain { limit }),
        |report, daemon_report| {
            daemon_report.add("purged_content_events", report.event_bytes_purged);
            daemon_report.add("retired_message_leaves", report.retired_message_leaves);
        },
    )
}

/// Per-instruction record carried from the purge transaction into the
/// post-commit retire phase. `needs_retire` is true for the kinds whose
/// retire walk we run (`Message`, `File`); it's false for kinds without
/// their own per-event leaf to retire (`Reaction`, `FileSlice`).
#[derive(Debug, Clone, Copy)]
struct DrainedInstruction {
    workspace_id: EventId,
    target_event_id: EventId,
    needs_retire: bool,
}

fn drain<R: EventRegistry>(
    store: &Store,
    registry: &R,
    limit: usize,
) -> Result<PurgeReport, String> {
    let (mut report, drained) = store
        .write_transaction(|store| drain_in_tx(store, limit).map_err(table_error))
        .map_err(|err| format!("drain content purge: {err}"))?;

    // For each drained instruction, run the retire-leaf step (if any) after
    // the purge transaction commits, then delete the queue rows. Retire
    // runs in its own transactions inside the encryption worker; doing
    // this after the purge commits avoids nesting event-admission
    // transactions inside the purge's own write transaction. Queue rows
    // are not deleted until retire succeeds, so a crash anywhere between
    // commit and retire is recoverable on restart by re-draining.
    for instr in drained {
        if instr.needs_retire {
            let coords = message_deletion::queries::purge_retire_coords_for(
                store,
                instr.workspace_id,
                instr.target_event_id,
            )?;
            if let Some(coords) = coords {
                let output = encryption_worker::run(
                    store,
                    registry,
                    encryption_worker::Work::RetireDeletedEventLeaf {
                        workspace_id: coords.workspace_id,
                        removal_frontier_id: coords.removal_frontier_id,
                        created_at_ms: coords.created_at_ms,
                        event_id_in_minute: coords.event_id_in_minute,
                    },
                )?;
                let encryption_worker::Output::RetiredDeletedEventLeaf(retired) = output else {
                    return Err(
                        "unexpected encryption worker output retiring deleted leaf".to_string()
                    );
                };
                report.event_bytes_purged += retired.purged_event_bytes;
                if retired.leaf_id.is_some() {
                    report.retired_message_leaves += 1;
                }
            }
        }
        // Idempotent cleanup: delete both queue rows in a small follow-up
        // transaction. Either row may already be gone on a re-drain after
        // partial-success crash; that is fine because the row deletes are
        // no-ops on absent keys.
        let queue_key = purge_instruction_key(instr.workspace_id, instr.target_event_id);
        store
            .write_transaction(|store| {
                store.delete_table_rows_in_tx(
                    message_deletion_schema::PURGE_INSTRUCTIONS,
                    vec![queue_key.clone()],
                )?;
                store.delete_table_rows_in_tx(
                    message_deletion_schema::PURGE_RETIRE_COORDS,
                    vec![queue_key.clone()],
                )?;
                Ok(())
            })
            .map_err(|err| format!("clear purge queue row: {err}"))?;
    }

    Ok(report)
}

fn drain_in_tx(
    store: &Store,
    limit: usize,
) -> Result<(PurgeReport, Vec<DrainedInstruction>), String> {
    let mut report = PurgeReport::default();
    let mut drained = Vec::new();
    let instructions = message_deletion::queries::list_purge_instructions(store, limit)?;
    for instr in instructions {
        let outcome = process_instruction(store, &instr, &mut report)?;
        if outcome.clear_instruction {
            drained.push(DrainedInstruction {
                workspace_id: instr.workspace_id,
                target_event_id: instr.target_event_id,
                needs_retire: outcome.needs_retire,
            });
        }
    }
    Ok((report, drained))
}

struct InstructionOutcome {
    needs_retire: bool,
    clear_instruction: bool,
}

fn process_instruction(
    store: &Store,
    instr: &PurgeInstruction,
    report: &mut PurgeReport,
) -> Result<InstructionOutcome, String> {
    match instr.kind {
        PurgeKind::Message => {
            process_message(store, instr.workspace_id, instr.target_event_id, report)
        }
        PurgeKind::Reaction => process_reaction(store, instr.target_event_id, report),
        PurgeKind::File => process_file(store, instr.workspace_id, instr.target_event_id, report),
        PurgeKind::FileSlice => process_file_slice(store, instr.target_event_id, report),
    }
}

/// Process one Message purge instruction.
///
/// If the bytes are still present, decode them, stamp retire coords, write
/// the tombstone, delete the read-model row, purge the canonical bytes,
/// and cascade-enqueue every reaction and file that references this
/// message. If the bytes are already gone (crash recovery after a
/// previous tick committed the purge tx but never finished retire), this
/// is a no-op for the in-tx work; the post-commit retire phase will read
/// the coords stamped in the prior tx and run the retire walk.
fn process_message(
    store: &Store,
    workspace_id: EventId,
    message_id: EventId,
    report: &mut PurgeReport,
) -> Result<InstructionOutcome, String> {
    let Some(bytes) = event_queries::event_bytes(store, &message_id)
        .map_err(|err| format!("load message event bytes: {err}"))?
    else {
        // Crash recovery has durable retire coords. Deletion-before-target
        // has neither bytes nor coords yet; keep the instruction queued.
        let has_coords =
            message_deletion::queries::purge_retire_coords_for(store, workspace_id, message_id)?
                .is_some();
        return Ok(InstructionOutcome {
            needs_retire: has_coords,
            clear_instruction: has_coords,
        });
    };
    report.scanned_events += 1;
    let envelope = message::codec::decode_signed(&bytes)?;
    let event = message::codec::decode(&envelope.payload)?;
    if event.workspace_id != workspace_id {
        return Ok(InstructionOutcome {
            needs_retire: false,
            clear_instruction: true,
        });
    }
    if !message_purge_is_authorized(store, message_id, &event)? {
        return Ok(InstructionOutcome {
            needs_retire: false,
            clear_instruction: true,
        });
    }

    // Stamp retire coords inside this tx, before the bytes are purged.
    // Using `replace_table_rows_in_tx` keeps the call idempotent under
    // re-drain: a second drain of the same instruction (which only
    // happens if bytes are still present) overwrites with the same coord
    // bytes.
    let coords = PurgeRetireCoords {
        workspace_id: event.workspace_id,
        target_event_id: message_id,
        removal_frontier_id: event.removal_frontier_id,
        created_at_ms: event.created_at_ms,
        event_id_in_minute: event.event_id_in_minute_derived(),
    };
    store
        .replace_table_rows_in_tx(vec![purge_retire_coords_row(&coords)])
        .map_err(|err| format!("stamp message retire coords: {err}"))?;

    let inserted = store
        .insert_table_rows_in_tx(vec![message::schema::message_tombstone_row(
            event.workspace_id,
            message_id,
            event.author_user_id,
            event.created_at_ms / message::types::UNIX_MINUTE_MS,
        )])
        .map_err(|err| format!("write message tombstone: {err}"))?;
    report.tombstones_written += inserted;

    report.message_rows_deleted += store
        .delete_table_rows_in_tx(
            message::schema::MESSAGES,
            vec![message::schema::message_key(event.workspace_id, message_id)],
        )
        .map_err(|err| format!("delete message row: {err}"))?;
    if purging::purge_event_storage_in_tx(store, &message_id)
        .map_err(|err| format!("purge message event: {err}"))?
    {
        report.event_bytes_purged += 1;
    }

    cascade_reactions_for_message(store, event.workspace_id, message_id)?;
    cascade_files_for_message(store, event.workspace_id, message_id)?;
    Ok(InstructionOutcome {
        needs_retire: true,
        clear_instruction: true,
    })
}

/// Process one Reaction cascade instruction (only authored as a cascade
/// from a Message purge, since reaction deletion is currently always a
/// side effect of message deletion).
fn process_reaction(
    store: &Store,
    reaction_id: EventId,
    report: &mut PurgeReport,
) -> Result<InstructionOutcome, String> {
    let Some(bytes) = event_queries::event_bytes(store, &reaction_id)
        .map_err(|err| format!("load reaction event bytes: {err}"))?
    else {
        // Crash recovery: reaction bytes already purged. Nothing to do
        // beyond letting the queue cleanup run after commit.
        return Ok(InstructionOutcome {
            needs_retire: false,
            clear_instruction: true,
        });
    };
    report.scanned_events += 1;
    let envelope = reaction::codec::decode_signed(&bytes)?;
    let event = reaction::codec::decode(&envelope.payload)?;
    report.reaction_rows_deleted += store
        .delete_table_rows_in_tx(
            reaction::schema::REACTIONS,
            vec![reaction::schema::reaction_key(
                event.workspace_id,
                reaction_id,
            )],
        )
        .map_err(|err| format!("delete reaction row: {err}"))?;
    if purging::purge_event_storage_in_tx(store, &reaction_id)
        .map_err(|err| format!("purge reaction event: {err}"))?
    {
        report.event_bytes_purged += 1;
    }
    Ok(InstructionOutcome {
        needs_retire: false,
        clear_instruction: true,
    })
}

/// Process one File purge instruction.
///
/// The file is purged when its parent message has been tombstoned (cascade
/// from message deletion) or when the file event itself carries an
/// author-signed deletion label from an admitted `file_deletion`. The
/// queue-driven design treats both as the same event: a `PurgeKind::File`
/// instruction was emitted, so the worker simply purges. The
/// authorization check still lives in the projectors: only an authorized
/// deletion (signed by the author or cascaded from a message tombstone)
/// can enqueue a `PurgeKind::File` instruction.
fn process_file(
    store: &Store,
    workspace_id: EventId,
    file_event_id: EventId,
    report: &mut PurgeReport,
) -> Result<InstructionOutcome, String> {
    let Some(bytes) = event_queries::event_bytes(store, &file_event_id)
        .map_err(|err| format!("load file event bytes: {err}"))?
    else {
        let has_coords =
            message_deletion::queries::purge_retire_coords_for(store, workspace_id, file_event_id)?
                .is_some();
        return Ok(InstructionOutcome {
            needs_retire: has_coords,
            clear_instruction: has_coords,
        });
    };
    report.scanned_events += 1;
    let envelope = file::codec::decode_signed(&bytes)?;
    let event = file::codec::decode(&envelope.payload)?;
    if event.workspace_id != workspace_id {
        return Ok(InstructionOutcome {
            needs_retire: false,
            clear_instruction: true,
        });
    }
    if !file_purge_is_authorized(store, file_event_id, &event)? {
        return Ok(InstructionOutcome {
            needs_retire: false,
            clear_instruction: true,
        });
    }

    let coords = PurgeRetireCoords {
        workspace_id: event.workspace_id,
        target_event_id: file_event_id,
        removal_frontier_id: event.removal_frontier_id,
        created_at_ms: event.created_at_ms,
        event_id_in_minute: event.event_id_in_minute_derived(),
    };
    store
        .replace_table_rows_in_tx(vec![purge_retire_coords_row(&coords)])
        .map_err(|err| format!("stamp file retire coords: {err}"))?;

    let primary_key = file::schema::file_key(event.workspace_id, file_event_id);
    let by_message_key =
        file::schema::file_by_message_key(event.workspace_id, event.message_id, file_event_id);
    let by_file_id_key =
        file::schema::file_by_file_id_key(event.workspace_id, event.file_id, file_event_id);
    report.file_rows_deleted += store
        .delete_table_rows_in_tx(file::schema::FILES, vec![primary_key])
        .map_err(|err| format!("delete file row: {err}"))?;
    let _ = store
        .delete_table_rows_in_tx(file::schema::FILES_BY_MESSAGE, vec![by_message_key])
        .map_err(|err| format!("delete files_by_message row: {err}"))?;
    let _ = store
        .delete_table_rows_in_tx(file::schema::FILES_BY_FILE_ID, vec![by_file_id_key])
        .map_err(|err| format!("delete files_by_file_id row: {err}"))?;

    // Cascade every slice projection row for this file_id. Slice canonical
    // bytes get enqueued as separate FileSlice instructions so they're
    // purged in their own dispatch branch.
    let slice_rows = store
        .table_rows_with_key_prefix(
            file_slice::schema::FILE_SLICES,
            &file_slice::schema::file_slice_prefix(event.workspace_id, event.file_id),
            usize::MAX,
        )
        .map_err(|err| format!("load file slice rows: {err}"))?;
    if !slice_rows.is_empty() {
        let mut cascade_rows = Vec::with_capacity(slice_rows.len());
        let slice_keys: Vec<Vec<u8>> = slice_rows.iter().map(|(key, _)| key.clone()).collect();
        for (key, value) in slice_rows {
            let row = file_slice::schema::decode_file_slice_row(&key, &value)?;
            cascade_rows.push(purge_instruction_row(
                event.workspace_id,
                row.slice_event_id,
                PurgeKind::FileSlice,
            ));
        }
        report.file_slice_rows_deleted += store
            .delete_table_rows_in_tx(file_slice::schema::FILE_SLICES, slice_keys)
            .map_err(|err| format!("delete file slice rows: {err}"))?;
        store
            .insert_table_rows_in_tx(cascade_rows)
            .map_err(|err| format!("enqueue cascade file slice instructions: {err}"))?;
    }

    if purging::purge_event_storage_in_tx(store, &file_event_id)
        .map_err(|err| format!("purge file event: {err}"))?
    {
        report.event_bytes_purged += 1;
    }
    Ok(InstructionOutcome {
        needs_retire: true,
        clear_instruction: true,
    })
}

/// Process one FileSlice cascade instruction. Only authored as a cascade
/// from File purge; slices do not have their own deletion event because
/// they are projection-time chunks of a single signed file descriptor.
fn process_file_slice(
    store: &Store,
    slice_event_id: EventId,
    report: &mut PurgeReport,
) -> Result<InstructionOutcome, String> {
    let Some(bytes) = event_queries::event_bytes(store, &slice_event_id)
        .map_err(|err| format!("load file slice event bytes: {err}"))?
    else {
        return Ok(InstructionOutcome {
            needs_retire: false,
            clear_instruction: true,
        });
    };
    report.scanned_events += 1;
    let envelope = file_slice::codec::decode_signed(&bytes)?;
    let (slice, _file_event_id) = file_slice::codec::decode(&envelope.payload)?;
    let slot_key =
        file_slice::schema::file_slice_key(slice.workspace_id, slice.file_id, slice.slice_number);
    report.file_slice_rows_deleted += store
        .delete_table_rows_in_tx(file_slice::schema::FILE_SLICES, vec![slot_key])
        .map_err(|err| format!("delete file slice row: {err}"))?;
    if purging::purge_event_storage_in_tx(store, &slice_event_id)
        .map_err(|err| format!("purge file slice event: {err}"))?
    {
        report.event_bytes_purged += 1;
    }
    Ok(InstructionOutcome {
        needs_retire: false,
        clear_instruction: true,
    })
}

fn message_purge_is_authorized(
    store: &Store,
    message_id: EventId,
    event: &message::types::MessageEvent,
) -> Result<bool, String> {
    if message::queries::message_tombstone_exists(store, event.workspace_id, message_id)? {
        return Ok(true);
    }
    let labels = event_queries::event_labels(store, &message_id)?;
    Ok(labels.iter().any(|label| {
        message_deletion::types::deletion_label_author(label)
            .map(|author| author == event.author_user_id)
            .unwrap_or(false)
    }))
}

fn file_purge_is_authorized(
    store: &Store,
    file_event_id: EventId,
    event: &file::types::FileEvent,
) -> Result<bool, String> {
    if message::queries::message_tombstone_exists(store, event.workspace_id, event.message_id)? {
        return Ok(true);
    }
    let labels = event_queries::event_labels(store, &file_event_id)?;
    Ok(labels.iter().any(|label| {
        file_deletion::types::deletion_label_author(label)
            .map(|author| author == event.author_user_id)
            .unwrap_or(false)
    }))
}

/// Cascade-enqueue every reaction in this workspace whose target is the
/// just-purged message. SEALED_REACTIONS carries the `target_message_id`
/// in its value, so a single workspace-prefix scan finds every match.
/// Reactions whose canonical bytes are already purged still need their
/// projection rows removed when the cascade runs, but we keep emission
/// simple: emit one `PurgeKind::Reaction` instruction per sealed row and
/// let the reaction handler be idempotent (bytes-missing branch is a
/// no-op).
fn cascade_reactions_for_message(
    store: &Store,
    workspace_id: EventId,
    message_id: EventId,
) -> Result<(), String> {
    let reactions = reaction::queries::list_for_workspace(store, workspace_id)
        .map_err(|err| format!("scan reactions for cascade: {err}"))?;
    let mut cascade_rows = Vec::new();
    for row in reactions {
        if row.target_message_id == message_id {
            cascade_rows.push(purge_instruction_row(
                workspace_id,
                row.reaction_id,
                PurgeKind::Reaction,
            ));
        }
    }
    if !cascade_rows.is_empty() {
        store
            .insert_table_rows_in_tx(cascade_rows)
            .map_err(|err| format!("enqueue cascade reaction instructions: {err}"))?;
    }
    Ok(())
}

/// Cascade-enqueue every file descriptor in this workspace whose parent
/// is the just-purged message. The `FILES_BY_MESSAGE` index lets a single
/// bounded prefix scan find every file by `(workspace_id, message_id)`
/// without touching the wider `FILES` table.
fn cascade_files_for_message(
    store: &Store,
    workspace_id: EventId,
    message_id: EventId,
) -> Result<(), String> {
    let by_message_rows = store
        .table_rows_with_key_prefix(
            file::schema::FILES_BY_MESSAGE,
            &file::schema::file_by_message_prefix(workspace_id, message_id),
            usize::MAX,
        )
        .map_err(|err| format!("load files_by_message for cascade: {err}"))?;
    if by_message_rows.is_empty() {
        return Ok(());
    }
    let mut cascade_rows = Vec::with_capacity(by_message_rows.len());
    for (_, value) in by_message_rows {
        if value.len() != 32 {
            return Err("files_by_message row value is malformed".to_string());
        }
        let mut file_event_id = [0; 32];
        file_event_id.copy_from_slice(&value);
        cascade_rows.push(purge_instruction_row(
            workspace_id,
            file_event_id,
            PurgeKind::File,
        ));
    }
    store
        .insert_table_rows_in_tx(cascade_rows)
        .map_err(|err| format!("enqueue cascade file instructions: {err}"))?;
    Ok(())
}

// Unused import guards for crate items referenced only by tests.
#[allow(dead_code)]
fn _unused_keep_imports_alive() -> Option<&'static str> {
    let _ = file_deletion::types::deletion_label;
    None
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::content::message::types::MessagePlaintext;
    use crate::protocol::event_modules::content::reaction::types::ReactionPlaintext;
    use crate::protocol::event_modules::schema::{self as event_schema, EventLabel};
    use crate::protocol::event_modules::types::{event_id, EventStatus};
    use crate::protocol::Protocol;
    use crate::workers::pipeline_helpers::event_lifecycle;

    use super::*;

    const WORKSPACE: EventId = [1; 32];
    const AUTHOR: EventId = [2; 32];
    const SIGNER: EventId = [3; 32];
    const FRONTIER: EventId = [4; 32];
    const KEY_SECRET: [u8; 32] = [5; 32];

    const LEAF_NODE_ID: EventId = [42; 32];

    fn message_record(text: &str) -> crate::protocol::event_modules::types::EventRecord {
        let output = message::commands::send(message::commands::SendMessage {
            workspace_id: WORKSPACE,
            created_at_ms: 10,
            author_user_id: AUTHOR,
            signer_endpoint_shared_id: SIGNER,
            signer_private_key: [9; 32],
            removal_frontier_id: FRONTIER,
            local_history_node_secret_id: LEAF_NODE_ID,
            leaf_node_secret: KEY_SECRET,
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [1; 32],
            text: text.to_string(),
        })
        .expect("message");
        output.events[0].record().clone()
    }

    fn reaction_record(
        target_message_id: EventId,
    ) -> crate::protocol::event_modules::types::EventRecord {
        let output = reaction::commands::post(reaction::commands::PostReaction {
            workspace_id: WORKSPACE,
            created_at_ms: 11,
            target_message_id,
            author_user_id: AUTHOR,
            signer_endpoint_shared_id: SIGNER,
            signer_private_key: [9; 32],
            removal_frontier_id: FRONTIER,
            local_history_node_secret_id: LEAF_NODE_ID,
            leaf_node_secret: KEY_SECRET,
            emoji: "+1".to_string(),
        })
        .expect("reaction");
        output.events[0].record().clone()
    }

    /// Seed a deletion instruction directly on the queue. Bypasses the
    /// projector path so tests can drive `drain` from explicit state.
    fn enqueue_message_purge(store: &Store, workspace_id: EventId, target_message_id: EventId) {
        store
            .insert_table_rows(vec![purge_instruction_row(
                workspace_id,
                target_message_id,
                PurgeKind::Message,
            )])
            .expect("enqueue message purge");
    }

    #[test]
    fn purges_deleted_message_and_attached_reaction_bytes_and_rows() {
        let store = Protocol::open_memory_store().expect("store");
        let message_record = message_record("delete me");
        let message_id = event_id(&message_record.canonical_bytes);
        let reaction_record = reaction_record(message_id);
        let reaction_id = event_id(&reaction_record.canonical_bytes);

        event_lifecycle::insert_event(&store, &message_record, EventStatus::Applied)
            .expect("insert message event");
        event_lifecycle::insert_event(&store, &reaction_record, EventStatus::Applied)
            .expect("insert reaction event");
        // Seal the sealed-reaction projection row so the cascade scan
        // finds the reaction by its target_message_id.
        let reaction_inner = reaction::codec::decode(
            &reaction::codec::decode_signed(&reaction_record.canonical_bytes)
                .expect("decode signed reaction")
                .payload,
        )
        .expect("decode reaction");
        store
            .insert_table_rows(vec![
                message::schema::message_row(
                    message_id,
                    SIGNER,
                    &MessagePlaintext {
                        workspace_id: WORKSPACE,
                        created_at_ms: 10,
                        author_user_id: AUTHOR,
                        removal_frontier_id: FRONTIER,
                        local_history_node_secret_id: LEAF_NODE_ID,
                        text: "delete me".to_string(),
                    },
                )
                .expect("message row"),
                reaction::schema::reaction_row(
                    reaction_id,
                    SIGNER,
                    &ReactionPlaintext {
                        workspace_id: WORKSPACE,
                        created_at_ms: 11,
                        target_message_id: message_id,
                        author_user_id: AUTHOR,
                        removal_frontier_id: FRONTIER,
                        local_history_node_secret_id: LEAF_NODE_ID,
                        emoji: "+1".to_string(),
                    },
                )
                .expect("reaction row"),
                reaction::schema::sealed_reaction_row(reaction_id, SIGNER, &reaction_inner)
                    .expect("sealed reaction row"),
            ])
            .expect("insert read rows");
        store
            .insert_table_rows(event_schema::event_label_rows(vec![EventLabel {
                event_id: message_id,
                label: message_deletion::types::deletion_label(&AUTHOR),
            }]))
            .expect("insert deletion label");

        enqueue_message_purge(&store, WORKSPACE, message_id);

        let protocol = Protocol::new();
        // First drain processes the message and cascade-enqueues the
        // reaction; second drain processes the reaction.
        let r1 = run(&store, &protocol, Work::Drain { limit: 10 }).expect("purge round 1");
        let r2 = run(&store, &protocol, Work::Drain { limit: 10 }).expect("purge round 2");

        assert_eq!(r1.tombstones_written, 1);
        assert!(r1.event_bytes_purged >= 1);
        assert_eq!(r2.reaction_rows_deleted, 1);
        assert!(r2.event_bytes_purged >= 1);
        assert!(event_queries::event_bytes(&store, &message_id)
            .expect("message bytes")
            .is_none());
        assert!(event_queries::event_bytes(&store, &reaction_id)
            .expect("reaction bytes")
            .is_none());
        assert!(
            message::queries::message_tombstone_exists(&store, WORKSPACE, message_id)
                .expect("tombstone")
        );
        assert!(
            message::queries::message_by_id(&store, WORKSPACE, message_id)
                .expect("message row")
                .is_none()
        );
        assert_eq!(
            reaction::queries::list_for_workspace(&store, WORKSPACE)
                .expect("reactions")
                .len(),
            0
        );
        // Queue rows cleared after retire succeeded on each instruction.
        assert!(!message_deletion::queries::has_purge_instructions(&store)
            .expect("queue empty after drain"));
    }

    #[test]
    fn purge_instruction_with_non_author_label_does_not_purge_message() {
        let store = Protocol::open_memory_store().expect("store");
        let message_record = message_record("keep me");
        let message_id = event_id(&message_record.canonical_bytes);
        event_lifecycle::insert_event(&store, &message_record, EventStatus::Applied)
            .expect("insert message event");
        store
            .insert_table_rows(event_schema::event_label_rows(vec![EventLabel {
                event_id: message_id,
                label: message_deletion::types::deletion_label(&[9; 32]),
            }]))
            .expect("insert non-author deletion label");
        enqueue_message_purge(&store, WORKSPACE, message_id);

        let protocol = Protocol::new();
        let report = run(&store, &protocol, Work::Drain { limit: 10 }).expect("purge");
        assert_eq!(report.event_bytes_purged, 0);
        assert!(event_queries::event_bytes(&store, &message_id)
            .expect("message bytes")
            .is_some());
        assert!(
            !message::queries::message_tombstone_exists(&store, WORKSPACE, message_id)
                .expect("tombstone")
        );
        assert!(
            !message_deletion::queries::has_purge_instructions(&store)
                .expect("bogus queue row cleared"),
            "unauthorized queue rows should be consumed rather than retried forever"
        );
    }

    #[test]
    fn delete_before_message_keeps_purge_instruction_until_target_arrives() {
        let store = Protocol::open_memory_store().expect("store");
        let missing_message_id = [99; 32];
        enqueue_message_purge(&store, WORKSPACE, missing_message_id);

        let protocol = Protocol::new();
        let report = run(&store, &protocol, Work::Drain { limit: 10 }).expect("purge");

        assert_eq!(report.event_bytes_purged, 0);
        assert!(
            message_deletion::queries::has_purge_instructions(&store)
                .expect("instruction retained"),
            "delete-before-target purge instructions must survive until target bytes arrive"
        );
    }

    #[test]
    fn second_drain_after_crash_uses_stamped_retire_coords_and_clears_queue() {
        // Simulate a crash that happened AFTER the purge transaction
        // committed (tombstone exists, bytes are gone, retire_coords
        // stamped) but BEFORE the queue row was deleted AND after retire
        // had already wiped the leaf (so RetireDeletedEventLeaf is now a
        // no-op). The next drain must:
        //   - not write a second tombstone
        //   - call RetireDeletedEventLeaf (it is idempotent)
        //   - delete both queue rows
        //   - preserve the existing tombstone
        let store = Protocol::open_memory_store().expect("store");
        let message_record = message_record("already purged");
        let message_id = event_id(&message_record.canonical_bytes);
        // NO message event bytes — already purged in the lost tick.
        // NO message read-model row — already deleted in the lost tick.
        // Pre-existing tombstone row from the lost tick.
        store
            .insert_table_rows(vec![message::schema::message_tombstone_row(
                WORKSPACE,
                message_id,
                AUTHOR,
                10 / message::types::UNIX_MINUTE_MS,
            )])
            .expect("insert tombstone");
        // Pre-existing purge_instruction row that the lost tick admitted.
        enqueue_message_purge(&store, WORKSPACE, message_id);
        // Pre-existing purge_retire_coords row stamped by the lost tick.
        let stamped_coords = PurgeRetireCoords {
            workspace_id: WORKSPACE,
            target_event_id: message_id,
            removal_frontier_id: FRONTIER,
            created_at_ms: 10,
            event_id_in_minute: [99; 32],
        };
        store
            .insert_table_rows(vec![purge_retire_coords_row(&stamped_coords)])
            .expect("insert stamped coords");

        let tombstones_before = store
            .table_row_count(message::schema::MESSAGE_TOMBSTONES)
            .expect("tombstone count before");

        let protocol = Protocol::new();
        run(&store, &protocol, Work::Drain { limit: 10 }).expect("re-drain after crash");

        let tombstones_after = store
            .table_row_count(message::schema::MESSAGE_TOMBSTONES)
            .expect("tombstone count after");
        assert_eq!(
            tombstones_before, tombstones_after,
            "re-drain must not write a duplicate tombstone for the same message_id"
        );
        // The pre-existing tombstone is preserved (no spurious row delete).
        assert!(
            message::queries::message_tombstone_exists(&store, WORKSPACE, message_id)
                .expect("tombstone still exists")
        );
        // Queue rows cleared by the re-drain.
        assert!(!message_deletion::queries::has_purge_instructions(&store)
            .expect("instructions cleared"));
        assert!(
            message_deletion::queries::purge_retire_coords_for(&store, WORKSPACE, message_id)
                .expect("coords lookup")
                .is_none(),
            "retire coords row must be cleared after the re-drain succeeds"
        );
    }
}
