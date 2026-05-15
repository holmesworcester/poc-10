//! Deferred sync intent constructors.
//!
//! Sync decides which facts must travel together. Transit owns the handler
//! payload and idempotence key for sending those facts on a connection.

use super::fact::{ConnectionId, EventId, KeyWrapId};

pub use crate::handlers::transit::TRANSIT_SEND_ON_CONNECTION as SEND_ON_CONNECTION;

pub fn send_on_connection_intent(
    connection_id: ConnectionId,
    event_id: EventId,
    dependency_id: EventId,
    key_wrap_id: KeyWrapId,
) -> crate::core::intents::Intent {
    crate::handlers::transit::send_on_connection_intent(
        crate::handlers::transit::TransitSendOnConnection {
            connection_id,
            fact_ids: vec![event_id, dependency_id, key_wrap_id],
        },
    )
}
