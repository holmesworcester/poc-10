//! Commands for emitting an `expired_minute` event.
//!
//! Slice 1 callers — currently only `disappearing_minute_expiry` daemon-step
//! work — must already know the minute_node's `local_history_node_secret_id`
//! to thread into canonical bytes. The worker derives this id by reading
//! the row at `(workspace, frontier, unix_minute, range_width=1, bit_depth=0,
//! event_id_prefix=[0;32])`.

use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{CommandOutput, ProposedEvent};

use super::codec;
use super::types::ExpiredMinuteEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpireMinute {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub unix_minute: u64,
    pub retired_minute_node_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpireMinuteOutput {
    pub expired_minute_event_id: EventId,
}

pub fn expire_minute(input: ExpireMinute) -> Result<CommandOutput<ExpireMinuteOutput>, String> {
    let event = ExpiredMinuteEvent {
        workspace_id: input.workspace_id,
        removal_frontier_id: input.removal_frontier_id,
        unix_minute: input.unix_minute,
        retired_minute_node_id: input.retired_minute_node_id,
    };
    let bytes = codec::encode(&event);
    let record = codec::record_from_bytes(bytes)?;
    let proposed = ProposedEvent::new(record);
    let event_id = proposed.event_id();
    Ok(CommandOutput::with_proposed_events(
        ExpireMinuteOutput {
            expired_minute_event_id: event_id,
        },
        vec![proposed],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_event_id_from_canonical_bytes() {
        let input = ExpireMinute {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            unix_minute: 100,
            retired_minute_node_id: [3; 32],
        };
        let first = expire_minute(input.clone()).expect("first");
        let second = expire_minute(input).expect("second");
        assert_eq!(
            first.value.expired_minute_event_id,
            second.value.expired_minute_event_id
        );
    }
}
