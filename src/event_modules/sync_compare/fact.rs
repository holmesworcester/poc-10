//! Sync compare fact shape for the poc-10 target tree.
//!
//! A compare is the negentropy equality query: "does your projected state for
//! this inclusive timestamp range have the same count and fingerprint as
//! mine?" The fact carries the connection id this query rides over, the
//! range, the sender's summary, and a flag indicating whether the peer
//! should respond with its own compare or with leaf-level have-id facts.
//!
//! Transit wrapping is a separate concern: the projector here only owns the
//! durable row layout. Routing this fact onto a connection happens in a
//! transit handler.

use crate::core::facts::FactId;

pub type ConnectionId = FactId;

pub const TIMESTAMP_DAY: u64 = 1_000_000;

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

    pub fn containing_day(timestamp: u64) -> Self {
        let start = (timestamp / TIMESTAMP_DAY) * TIMESTAMP_DAY;
        Self {
            start,
            end: start.saturating_add(TIMESTAMP_DAY - 1),
        }
    }

    pub fn next_day_after(timestamp: u64) -> u64 {
        ((timestamp / TIMESTAMP_DAY) + 1) * TIMESTAMP_DAY
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RangeSummary {
    pub count: u64,
    pub fingerprint: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncCompareFact {
    pub connection_id: ConnectionId,
    pub range: TimestampRange,
    pub summary: RangeSummary,
    pub response_requested: bool,
}
