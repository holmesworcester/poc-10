//! Compare-driven sync commands.
//!
//! This is the POC's range-negentropy reconciliation engine. A peer asks "does
//! this timestamp range have the same count and fingerprint?" If not, the
//! responder answers with child compares until a timestamp leaf can advertise
//! concrete ids. Missing ids become need ids; received need ids queue durable
//! event ids to the connection outbox. The command emits event records and ids
//! only: transit wrapping and TCP framing are outside sync.

use crate::protocol::event_modules::types::{EventId, EventIndexEntry};

use super::super::have_id::{self, types::HaveIdEvent};
use super::super::need_id::{self, types::NeedIdEvent};
use super::types::{CompareEvent, RangeSummary, TimestampRange};

const MAX_HAVE_IDS_PER_RANGE: usize = 64;

pub trait ReadContext {
    /// Summarize every shared event whose timestamp is inside the range.
    fn summary(&self, range: TimestampRange) -> Result<RangeSummary, String>;
    /// Enumerate ids in one timestamp range when summaries differ.
    fn ids_in_range(&self, range: TimestampRange) -> Result<Vec<EventIndexEntry>, String>;
    /// Check whether an advertised id is already present locally.
    fn has_event(&self, event_id: &EventId) -> Result<bool, String>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub sent_events: usize,
    pub events: Vec<crate::protocol::event_modules::types::EventRecord>,
    pub send_event_ids: Vec<EventId>,
}

pub fn start(context: &impl ReadContext, connection_id: EventId) -> Result<SyncReport, String> {
    // Manual start sends only the root compare. The rest of the exchange is
    // driven by projected inbound compare rows.
    let range = TimestampRange::ROOT;
    let mut report = SyncReport::default();
    report
        .events
        .push(super::codec::outbound_record(CompareEvent {
            connection_id,
            range,
            summary: context.summary(range)?,
            response_requested: true,
        })?);
    Ok(report)
}

pub fn handle_inbound_event(
    context: &impl ReadContext,
    expected_connection_id: EventId,
    bytes: &[u8],
) -> Result<SyncReport, String> {
    let mut report = SyncReport::default();
    if super::codec::is_event(bytes) {
        let event = super::codec::decode(bytes)?;
        ensure_connection(event.connection_id, expected_connection_id)?;
        let local = context.summary(event.range)?;
        if local != event.summary {
            let events = compare_response(
                context,
                event.connection_id,
                event.range,
                local,
                event.summary,
                event.response_requested,
            )?;
            report.events.extend(events);
        }
        return Ok(report);
    }
    if have_id::codec::is_event(bytes) {
        let event = have_id::codec::decode(bytes)?;
        ensure_connection(event.connection_id, expected_connection_id)?;
        if !context.has_event(&event.id)? {
            report
                .events
                .push(need_id::codec::outbound_record(NeedIdEvent {
                    connection_id: event.connection_id,
                    id: event.id,
                })?);
        }
        return Ok(report);
    }
    if need_id::codec::is_event(bytes) {
        let event = need_id::codec::decode(bytes)?;
        ensure_connection(event.connection_id, expected_connection_id)?;
        if context.has_event(&event.id)? {
            report.send_event_ids.push(event.id);
            report.sent_events = 1;
        }
        return Ok(report);
    }
    Err("not an inbound sync event".to_string())
}

fn ensure_connection(
    connection_id: EventId,
    expected_connection_id: EventId,
) -> Result<(), String> {
    if connection_id != expected_connection_id {
        return Err("sync event used a different connection id".to_string());
    }
    Ok(())
}

fn compare_response(
    context: &impl ReadContext,
    connection_id: EventId,
    range: TimestampRange,
    local: RangeSummary,
    remote: RangeSummary,
    response_requested: bool,
) -> Result<Vec<crate::protocol::event_modules::types::EventRecord>, String> {
    let mut records = Vec::new();
    let entries = context.ids_in_range(range)?;
    if entries.is_empty() {
        if response_requested {
            records.push(super::codec::outbound_record(CompareEvent {
                connection_id,
                range,
                summary: local,
                response_requested: false,
            })?);
        }
        return Ok(records);
    }

    if entries.len() <= MAX_HAVE_IDS_PER_RANGE {
        for entry in entries {
            records.push(have_id::codec::outbound_record(HaveIdEvent {
                connection_id,
                timestamp: entry.timestamp,
                id: entry.event_id,
            })?);
        }
        if response_requested && remote.count > 0 {
            records.push(super::codec::outbound_record(CompareEvent {
                connection_id,
                range,
                summary: local,
                response_requested: false,
            })?);
        }
        return Ok(records);
    }

    let min_timestamp = entries
        .first()
        .map(|entry| entry.timestamp)
        .expect("entries not empty");
    let max_timestamp = entries
        .last()
        .map(|entry| entry.timestamp)
        .expect("entries not empty");
    if min_timestamp == max_timestamp {
        for entry in entries {
            records.push(have_id::codec::outbound_record(HaveIdEvent {
                connection_id,
                timestamp: entry.timestamp,
                id: entry.event_id,
            })?);
        }
        if response_requested && remote.count > 0 {
            records.push(super::codec::outbound_record(CompareEvent {
                connection_id,
                range,
                summary: local,
                response_requested: false,
            })?);
        }
        return Ok(records);
    }

    if range.start < min_timestamp {
        let empty_left = TimestampRange {
            start: range.start,
            end: min_timestamp - 1,
        };
        records.push(super::codec::outbound_record(CompareEvent {
            connection_id,
            range: empty_left,
            summary: RangeSummary::default(),
            response_requested: true,
        })?);
    }
    if max_timestamp < range.end {
        let empty_right = TimestampRange {
            start: max_timestamp + 1,
            end: range.end,
        };
        records.push(super::codec::outbound_record(CompareEvent {
            connection_id,
            range: empty_right,
            summary: RangeSummary::default(),
            response_requested: true,
        })?);
    }

    let local_range = TimestampRange {
        start: min_timestamp,
        end: max_timestamp,
    };
    if let Some((left, right)) = local_range.split() {
        for child in [left, right] {
            records.push(super::codec::outbound_record(CompareEvent {
                connection_id,
                range: child,
                summary: context.summary(child)?,
                response_requested: true,
            })?);
        }
        return Ok(records);
    }
    Ok(records)
}
