//! Types for local invite acceptance.
//!
//! `InviteAcceptedEvent` is not a shared protocol deletion, grant, or membership
//! event. It is a local replayable statement that this endpoint accepted an
//! invite link and recorded the matching scoped invite secret. Shared authority
//! still comes from the signed user/device/invite-server events admitted through
//! the normal identity graph.

use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteAcceptedEvent {
    pub workspace_id: EventId,
    pub invite_event_id: EventId,
    pub invite_secret_event_id: EventId,
    pub bootstrap_hash: EventId,
    pub accepted_endpoint_id: EndpointId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteAcceptedRow {
    pub accepted_endpoint_id: EndpointId,
    pub workspace_id: EventId,
    pub invite_event_id: EventId,
    pub invite_accepted_event_id: EventId,
    pub invite_secret_event_id: EventId,
    pub bootstrap_hash: EventId,
}
