//! Codec for local-only `expired_minute` events.
//!
//! Layout:
//!
//! ```text
//! type(1) || workspace(32) || removal_frontier(32)
//!   || unix_minute(8) || retired_minute_node_id(32)
//! ```

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::ExpiredMinuteEvent;

pub const TYPE_EXPIRED_MINUTE: u8 = 146;
pub const EXPIRED_MINUTE_WIRE_SIZE: usize = 1 + 32 + 32 + 8 + 32;

pub fn encode(event: &ExpiredMinuteEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(EXPIRED_MINUTE_WIRE_SIZE);
    out.u8(TYPE_EXPIRED_MINUTE);
    out.id(&event.workspace_id);
    out.id(&event.removal_frontier_id);
    out.u64(event.unix_minute);
    out.id(&event.retired_minute_node_id);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<ExpiredMinuteEvent, String> {
    let mut reader = Reader::new(bytes, "expired_minute event");
    let tag = reader.u8()?;
    if tag != TYPE_EXPIRED_MINUTE {
        return Err("expected expired_minute event".to_string());
    }
    let workspace_id = reader.id()?;
    let removal_frontier_id = reader.id()?;
    let unix_minute = reader.u64()?;
    let retired_minute_node_id = reader.id()?;
    reader.finish()?;
    Ok(ExpiredMinuteEvent {
        workspace_id,
        removal_frontier_id,
        unix_minute,
        retired_minute_node_id,
    })
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    let timestamp = event.unix_minute.saturating_mul(60_000);
    Ok(EventRecord {
        timestamp,
        body_len: EXPIRED_MINUTE_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        // Dependencies: the frontier for which we are retiring this minute,
        // and the retired minute_node secret event itself. The
        // retired_minute_node_id is a local_history_node_secret event id,
        // already a durable local event in this peer's store.
        dependencies: vec![event.removal_frontier_id, event.retired_minute_node_id],
        workspace_id: Some(event.workspace_id),
        scope: EventScope::Local,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> ExpiredMinuteEvent {
        ExpiredMinuteEvent {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            unix_minute: 100,
            retired_minute_node_id: [3; 32],
        }
    }

    #[test]
    fn roundtrips_expired_minute_event() {
        let bytes = encode(&event());
        assert_eq!(bytes.len(), EXPIRED_MINUTE_WIRE_SIZE);
        assert_eq!(decode(&bytes).expect("decode"), event());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = encode(&event());
        bytes.push(0);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn record_is_local_with_frontier_and_node_dependencies() {
        let bytes = encode(&event());
        let record = record_from_bytes(bytes.clone()).expect("record");
        assert_eq!(record.scope, EventScope::Local);
        assert_eq!(record.dependencies, vec![[2; 32], [3; 32]]);
        assert_eq!(record.workspace_id, Some([1; 32]));
    }
}
