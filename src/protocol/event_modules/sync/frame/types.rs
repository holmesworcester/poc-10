//! Sync frame item types.
//!
//! The frame groups compare, have, need, and data items under one connection.
//! Items are deliberately not separate durable events; the transient frame event
//! is the unit that gets queued and deduped for sending.

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
