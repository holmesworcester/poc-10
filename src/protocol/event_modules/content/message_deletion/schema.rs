//! Content purge queue tables.
//!
//! Two durable tables together implement a crash-safe purge queue:
//!
//!   * `content.purge_instructions.v1` is projector-written. Each row marks
//!     one target event id that should be purged, tagged with the kind of
//!     event (message / reaction / file / file_slice). Projectors emit
//!     these rows via `ProjectionOutput.rows` from the same transaction
//!     that admits the deletion event, so the row is durable before
//!     control returns to the caller.
//!   * `content.purge_retire_coords.v1` is worker-written. The
//!     content_purge worker decodes the target message/file/slice/reaction
//!     bytes inside the purge transaction (they are still on disk pre-
//!     purge), extracts the retire coordinates, and stamps a row here
//!     before purging the bytes. Because the row is written in the same
//!     transaction as the purge, a crash that leaves the message bytes
//!     gone still leaves the coords available for the retire walk.
//!
//! Both tables are durable so a crash anywhere between purge commit and
//! retire-walk completion is recoverable on restart: the worker re-drains,
//! the purge step is idempotent, the retire step reads coords from the
//! second table, and only after retire succeeds do the queue rows get
//! deleted. Projectors do not query storage (rules_boundary forbids
//! `&Store` in projector.rs), so they cannot themselves extract retire
//! coords — splitting the queue lets each side write only what it can see.
//!
//! See `content_purge` worker docs for the drain protocol; this module is
//! pure schema + row constructors and does not act on its own tables.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;

pub const PURGE_INSTRUCTIONS: TableName = TableName::new("content.purge_instructions");
pub const PURGE_RETIRE_COORDS: TableName = TableName::new("content.purge_retire_coords");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("content.purge_instructions.v1", PURGE_INSTRUCTIONS),
    Schema::durable_row_table("content.purge_retire_coords.v1", PURGE_RETIRE_COORDS),
];

/// Kind tag stored in the `purge_instructions` row value.
///
/// Numeric encoding is part of the durable shape and must not change without
/// a schema migration. The worker drains the queue and dispatches on this
/// tag to choose which purge branch to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeKind {
    Message = 0,
    Reaction = 1,
    File = 2,
    FileSlice = 3,
}

impl PurgeKind {
    pub fn from_byte(byte: u8) -> Result<Self, String> {
        match byte {
            0 => Ok(PurgeKind::Message),
            1 => Ok(PurgeKind::Reaction),
            2 => Ok(PurgeKind::File),
            3 => Ok(PurgeKind::FileSlice),
            other => Err(format!("unknown purge kind tag {other}")),
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Build the composite key shared by both queue tables.
pub fn purge_instruction_key(workspace_id: EventId, target_event_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&target_event_id);
    key
}

/// Row written by a deletion projector to enqueue one target event for
/// purging. The kind tag lets the worker dispatch to the right branch
/// without having to load the bytes first.
pub fn purge_instruction_row(
    workspace_id: EventId,
    target_event_id: EventId,
    kind: PurgeKind,
) -> TableRow {
    TableRow {
        table: PURGE_INSTRUCTIONS,
        key: purge_instruction_key(workspace_id, target_event_id),
        value: vec![kind.as_byte()],
    }
}

/// Decoded view of a `purge_instructions` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeInstruction {
    pub workspace_id: EventId,
    pub target_event_id: EventId,
    pub kind: PurgeKind,
}

pub fn decode_purge_instruction(key: &[u8], value: &[u8]) -> Result<PurgeInstruction, String> {
    if key.len() != 64 {
        return Err("purge_instruction key is malformed".to_string());
    }
    if value.len() != 1 {
        return Err("purge_instruction value is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut target_event_id = [0; 32];
    target_event_id.copy_from_slice(&key[32..64]);
    let kind = PurgeKind::from_byte(value[0])?;
    Ok(PurgeInstruction {
        workspace_id,
        target_event_id,
        kind,
    })
}

/// Decoded view of a `purge_retire_coords` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeRetireCoords {
    pub workspace_id: EventId,
    pub target_event_id: EventId,
    pub removal_frontier_id: EventId,
    pub created_at_ms: u64,
    pub event_id_in_minute: EventId,
}

/// Row written by the content_purge worker inside the purge transaction to
/// stamp the retire coordinates extracted from the target event's bytes.
/// Survives the transaction so post-commit retire walks can run from
/// durable state alone.
pub fn purge_retire_coords_row(coords: &PurgeRetireCoords) -> TableRow {
    let mut value = Vec::with_capacity(32 + 8 + 32);
    value.extend_from_slice(&coords.removal_frontier_id);
    value.extend_from_slice(&coords.created_at_ms.to_be_bytes());
    value.extend_from_slice(&coords.event_id_in_minute);
    TableRow {
        table: PURGE_RETIRE_COORDS,
        key: purge_instruction_key(coords.workspace_id, coords.target_event_id),
        value,
    }
}

pub fn decode_purge_retire_coords(key: &[u8], value: &[u8]) -> Result<PurgeRetireCoords, String> {
    if key.len() != 64 {
        return Err("purge_retire_coords key is malformed".to_string());
    }
    if value.len() != 72 {
        return Err("purge_retire_coords value is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut target_event_id = [0; 32];
    target_event_id.copy_from_slice(&key[32..64]);
    let mut removal_frontier_id = [0; 32];
    removal_frontier_id.copy_from_slice(&value[..32]);
    let mut created_at_bytes = [0; 8];
    created_at_bytes.copy_from_slice(&value[32..40]);
    let created_at_ms = u64::from_be_bytes(created_at_bytes);
    let mut event_id_in_minute = [0; 32];
    event_id_in_minute.copy_from_slice(&value[40..72]);
    Ok(PurgeRetireCoords {
        workspace_id,
        target_event_id,
        removal_frontier_id,
        created_at_ms,
        event_id_in_minute,
    })
}

#[cfg(test)]
mod tests {
    use crate::protocol::Protocol;

    use super::super::queries::has_purge_instructions;
    use super::*;

    #[test]
    fn purge_instruction_row_encodes_workspace_and_kind_tag() {
        let row = purge_instruction_row([7; 32], [8; 32], PurgeKind::Message);
        assert_eq!(row.table, PURGE_INSTRUCTIONS);
        assert_eq!(row.key.len(), 64);
        assert_eq!(row.key[..32], [7; 32]);
        assert_eq!(row.key[32..], [8; 32]);
        assert_eq!(row.value, vec![0]);

        let row = purge_instruction_row([7; 32], [8; 32], PurgeKind::Reaction);
        assert_eq!(row.value, vec![1]);

        let row = purge_instruction_row([7; 32], [8; 32], PurgeKind::File);
        assert_eq!(row.value, vec![2]);

        let row = purge_instruction_row([7; 32], [8; 32], PurgeKind::FileSlice);
        assert_eq!(row.value, vec![3]);
    }

    #[test]
    fn purge_instruction_decode_round_trips() {
        let row = purge_instruction_row([7; 32], [8; 32], PurgeKind::Reaction);
        let decoded = decode_purge_instruction(&row.key, &row.value).expect("decode");
        assert_eq!(decoded.workspace_id, [7; 32]);
        assert_eq!(decoded.target_event_id, [8; 32]);
        assert_eq!(decoded.kind, PurgeKind::Reaction);
    }

    #[test]
    fn purge_instruction_decode_rejects_unknown_kind() {
        let key = purge_instruction_key([0; 32], [0; 32]);
        let err = decode_purge_instruction(&key, &[99]).expect_err("unknown kind");
        assert!(err.contains("unknown purge kind tag 99"));
    }

    #[test]
    fn purge_retire_coords_round_trip() {
        let coords = PurgeRetireCoords {
            workspace_id: [1; 32],
            target_event_id: [2; 32],
            removal_frontier_id: [3; 32],
            created_at_ms: 0x12_34_56_78_9A_BC_DE_F0,
            event_id_in_minute: [4; 32],
        };
        let row = purge_retire_coords_row(&coords);
        assert_eq!(row.table, PURGE_RETIRE_COORDS);
        assert_eq!(row.value.len(), 72);
        let decoded = decode_purge_retire_coords(&row.key, &row.value).expect("decode");
        assert_eq!(decoded, coords);
    }

    #[test]
    fn purge_instructions_round_trips_through_has_query() {
        let store = Protocol::open_memory_store().expect("store");
        assert!(!has_purge_instructions(&store).expect("empty"));
        store
            .insert_table_rows(vec![purge_instruction_row(
                [3; 32],
                [4; 32],
                PurgeKind::Message,
            )])
            .expect("insert pending row");
        assert!(has_purge_instructions(&store).expect("populated"));
    }

    #[test]
    fn purge_instructions_table_survives_reopens() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("purge-instructions.db");
        {
            let store = Protocol::open_store(&path).expect("open first");
            store
                .insert_table_rows(vec![purge_instruction_row(
                    [9; 32],
                    [10; 32],
                    PurgeKind::Message,
                )])
                .expect("insert pending row");
            assert!(has_purge_instructions(&store).expect("populated"));
        }
        let store = Protocol::open_store(&path).expect("reopen");
        assert!(
            has_purge_instructions(&store).expect("after reopen"),
            "purge_instructions must be durable so crash recovery sees the queue"
        );
    }
}
