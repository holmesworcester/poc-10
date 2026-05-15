//! Deferred sync intent layouts.

use crate::core::intents::{Intent, IntentExecution, IntentKind};

use super::context;
use super::fact::{ConnectionId, EventId, KeyId};

pub const SEND_ON_CONNECTION: &str = "send_on_connection";

pub fn send_on_connection_intent(
    connection_id: ConnectionId,
    event_id: EventId,
    dependency_id: EventId,
    key_id: KeyId,
) -> Intent {
    let mut payload = Vec::with_capacity(96);
    payload.extend_from_slice(&event_id);
    payload.extend_from_slice(&dependency_id);
    payload.extend_from_slice(&key_id);
    Intent::new(
        IntentKind::new(SEND_ON_CONNECTION).expect("valid sync intent kind"),
        IntentExecution::Deferred,
        context::send_on_connection_key(connection_id, event_id),
        payload,
    )
}
