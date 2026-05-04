//! Compare-driven sync commands.
//!
//! This is the POC's simple reconciliation engine. A peer asks "do these bucket
//! summaries match?" If not, the responder sends have ids for differing
//! buckets; missing ids become need ids; received need ids queue durable event
//! ids to the connection outbox. The command emits event records and ids only:
//! transit wrapping and TCP framing are outside sync.

use crate::protocol::event_modules::sync::types::SyncDirection;
use crate::protocol::event_modules::types::EventId;

use super::super::have_id::{self, types::HaveIdEvent};
use super::super::need_id::{self, types::NeedIdEvent};
use super::queries;
use super::types::{BucketSummary, CompareEvent, BUCKETS};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub sent_events: usize,
    pub events: Vec<crate::protocol::event_modules::types::EventRecord>,
    pub send_event_ids: Vec<EventId>,
}

pub fn start(
    context: &impl queries::ReadContext,
    connection_id: EventId,
) -> Result<SyncReport, String> {
    // Manual start sends a full compare and, for the current simple protocol,
    // all have ids. The latter is intentionally easy to reason about and relies
    // on outbox idempotence rather than round state.
    let mut report = SyncReport::default();
    report
        .events
        .push(super::codec::outbound_record(CompareEvent {
            direction: SyncDirection::Outbound,
            connection_id,
            summary: context.summary()?,
        })?);
    for event in all_have_items(context, connection_id)? {
        report.events.push(have_id::codec::outbound_record(event)?);
    }
    Ok(report)
}

pub fn handle_inbound_event(
    context: &impl queries::ReadContext,
    expected_connection_id: EventId,
    bytes: &[u8],
) -> Result<SyncReport, String> {
    let mut report = SyncReport::default();
    if super::codec::is_event(bytes) {
        let event = super::codec::decode(bytes)?;
        ensure_inbound(event.direction, event.connection_id, expected_connection_id)?;
        let local = context.summary()?;
        if local != event.summary {
            for have in have_items_for_compare(context, event.connection_id, local, event.summary)?
            {
                report.events.push(have_id::codec::outbound_record(have)?);
            }
        }
        return Ok(report);
    }
    if have_id::codec::is_event(bytes) {
        let event = have_id::codec::decode(bytes)?;
        ensure_inbound(event.direction, event.connection_id, expected_connection_id)?;
        if !context.has_event(&event.id)? {
            report
                .events
                .push(need_id::codec::outbound_record(NeedIdEvent {
                    direction: SyncDirection::Outbound,
                    connection_id: event.connection_id,
                    id: event.id,
                })?);
        }
        return Ok(report);
    }
    if need_id::codec::is_event(bytes) {
        let event = need_id::codec::decode(bytes)?;
        ensure_inbound(event.direction, event.connection_id, expected_connection_id)?;
        if context.has_event(&event.id)? {
            report.send_event_ids.push(event.id);
            report.sent_events = 1;
        }
        return Ok(report);
    }
    Err("not an inbound sync event".to_string())
}

fn ensure_inbound(
    direction: SyncDirection,
    connection_id: EventId,
    expected_connection_id: EventId,
) -> Result<(), String> {
    if direction != SyncDirection::Inbound {
        return Err("sync worker received an outbound sync event".to_string());
    }
    if connection_id != expected_connection_id {
        return Err("sync event used a different connection id".to_string());
    }
    Ok(())
}

fn all_have_items(
    context: &impl queries::ReadContext,
    connection_id: EventId,
) -> Result<Vec<HaveIdEvent>, String> {
    let mut items = Vec::new();
    for bucket in 0..BUCKETS {
        let ids = context.ids_in_bucket(bucket as u8)?;
        for id in ids {
            items.push(HaveIdEvent {
                direction: SyncDirection::Outbound,
                connection_id,
                bucket: bucket as u8,
                id,
            });
        }
    }
    Ok(items)
}

fn have_items_for_compare(
    context: &impl queries::ReadContext,
    connection_id: EventId,
    local: [BucketSummary; BUCKETS],
    remote: [BucketSummary; BUCKETS],
) -> Result<Vec<HaveIdEvent>, String> {
    let mut items = Vec::new();
    for bucket in differing_buckets(&local, &remote) {
        let ids = context.ids_in_bucket(bucket)?;
        for id in ids {
            items.push(HaveIdEvent {
                direction: SyncDirection::Outbound,
                connection_id,
                bucket,
                id,
            });
        }
    }
    Ok(items)
}

fn differing_buckets(
    local: &[BucketSummary; BUCKETS],
    remote: &[BucketSummary; BUCKETS],
) -> Vec<u8> {
    local
        .iter()
        .zip(remote.iter())
        .enumerate()
        .filter_map(|(idx, (left, right))| (left != right).then_some(idx as u8))
        .collect()
}
