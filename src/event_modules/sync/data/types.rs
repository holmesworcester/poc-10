use crate::store::EventId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataEvent {
    pub connection_id: EventId,
    pub items: Vec<Vec<u8>>,
}
