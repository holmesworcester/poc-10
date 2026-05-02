use crate::event_modules::connection::connection_record::types::ConnectionId;
use crate::event_modules::identity::endpoint::types::EndpointId;
use crate::store::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckEvent {
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub request_id: EventId,
    pub connection_id: ConnectionId,
}
