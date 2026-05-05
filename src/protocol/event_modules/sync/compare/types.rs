//! Compare event types.
//!
//! Sync range compare event types.
//!
//! A compare is the negentropy equality query: "does your projected state for
//! this timestamp range have the same count and fingerprint as mine?" Ranges
//! are inclusive and split by timestamp until a leaf can advertise concrete ids.

use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampRange {
    pub start: u64,
    pub end: u64,
}

impl TimestampRange {
    pub const ROOT: Self = Self {
        start: 0,
        end: u64::MAX,
    };

    pub fn is_splittable(self) -> bool {
        self.start < self.end
    }

    pub fn split(self) -> Option<(Self, Self)> {
        if !self.is_splittable() {
            return None;
        }
        let mid = self.start + (self.end - self.start) / 2;
        Some((
            Self {
                start: self.start,
                end: mid,
            },
            Self {
                start: mid + 1,
                end: self.end,
            },
        ))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RangeSummary {
    pub count: u64,
    pub fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareEvent {
    pub connection_id: EventId,
    pub range: TimestampRange,
    pub summary: RangeSummary,
    pub response_requested: bool,
}
