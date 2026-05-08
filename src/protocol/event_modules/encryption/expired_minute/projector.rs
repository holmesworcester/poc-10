//! Projector for `expired_minute` events.
//!
//! The projector is row-only per RULES.md. It writes the tombstone row for
//! the retired minute_node and exact-row-deletes the minute_node's
//! `local_history_node_secrets` row. Cleanup of the leaf rows under the
//! minute, the read-model message rows, the sealed_messages rows, and the
//! canonical message bytes happens in the `disappearing_minute_expiry`
//! daemon-step worker outside the projector's transaction — that work
//! mutates storage and is not row-shaped.

use crate::protocol::event_modules::types::event_id;
use crate::protocol::event_modules::worker::{ProjectionOutput, TableDelete};

use super::super::local_history_node_secret::schema as history_schema;
use super::super::local_history_node_secret::types::TIME_TREE_BIT_DEPTH;
use super::codec;

/// Width of the time-tree leaf (the minute_node). Matches the convention in
/// `local_history_node_secret`: minute_nodes are at `range_width=1`,
/// `bit_depth=0`, `event_id_prefix=[0;32]`.
const MINUTE_RANGE_WIDTH: u64 = 1;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let event = codec::decode(bytes)?;
    let expired_minute_event_id = event_id(bytes);

    // Write the tombstone row pointing the retired minute_node at the
    // expired_minute event id. Both peers reach this row deterministically:
    // canonical bytes are byte-equal across peers, so the event id is byte-
    // equal, the minute_node id is byte-equal (deterministic from shared
    // frontier secret), and the row key is byte-equal.
    let tombstone = history_schema::local_history_node_tombstone_key(
        event.workspace_id,
        event.removal_frontier_id,
        event.retired_minute_node_id,
    );
    let tombstone_value = expired_minute_event_id.to_vec();
    let mut output = ProjectionOutput::rows(vec![crate::core::store::TableRow {
        table: history_schema::LOCAL_HISTORY_NODE_TOMBSTONES,
        key: tombstone,
        value: tombstone_value,
    }]);

    // Exact-row-delete the minute_node `local_history_node_secrets` row.
    // The leaf rows beneath it and the message read-model rows are cleaned
    // up by the daemon-step worker outside this transaction.
    let minute_node_key = history_schema::local_history_node_secret_key(
        event.workspace_id,
        event.removal_frontier_id,
        event.unix_minute,
        MINUTE_RANGE_WIDTH,
        TIME_TREE_BIT_DEPTH,
        [0; 32],
    );
    output.deletes.push(TableDelete {
        table: history_schema::LOCAL_HISTORY_NODE_SECRETS,
        key: minute_node_key,
    });

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::super::types::ExpiredMinuteEvent;
    use super::*;

    #[test]
    fn writes_tombstone_and_minute_node_delete() {
        let event = ExpiredMinuteEvent {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            unix_minute: 100,
            retired_minute_node_id: [3; 32],
        };
        let bytes = codec::encode(&event);
        let output = project(&bytes).expect("project expired_minute");
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, history_schema::LOCAL_HISTORY_NODE_TOMBSTONES);
        assert_eq!(output.deletes.len(), 1);
        assert_eq!(
            output.deletes[0].table,
            history_schema::LOCAL_HISTORY_NODE_SECRETS
        );
    }
}
