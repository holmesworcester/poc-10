use super::super::{compare, data, have_id, need_id};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub more: bool,
    pub items: Vec<SyncItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncItem {
    Compare(Box<compare::types::CompareEvent>),
    HaveId(have_id::types::HaveIdEvent),
    NeedId(need_id::types::NeedIdEvent),
    Data(data::types::DataEvent),
}
