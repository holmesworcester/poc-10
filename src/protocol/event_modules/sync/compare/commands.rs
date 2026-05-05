//! Compare-driven sync commands.
//!
//! This is the POC's simple reconciliation engine. A peer asks "do these bucket
//! summaries match?" If not, the responder sends have ids for differing
//! buckets; missing ids become need ids; received need ids queue durable event
//! ids to the connection outbox. The command emits event records and ids only:
//! transit wrapping and TCP framing are outside sync.

use crate::protocol::event_modules::types::EventId;

use super::super::have_id::{self, types::HaveIdEvent};
use super::super::need_id::{self, types::NeedIdEvent};
use super::types::{BucketSummary, CompareEvent, BUCKETS};

pub trait ReadContext {
    /// Summarize every shared event bucket.
    fn summary(&self) -> Result<[BucketSummary; BUCKETS], String>;
    /// Enumerate ids in one bucket when summaries differ.
    fn ids_in_bucket(&self, bucket: u8) -> Result<Vec<EventId>, String>;
    /// Check whether an advertised id is already present locally.
    fn has_event(&self, event_id: &EventId) -> Result<bool, String>;
    /// Check whether a locally present id may be served to this connection.
    fn can_send_event(&self, event_id: &EventId) -> Result<bool, String> {
        self.has_event(event_id)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub sent_events: usize,
    pub events: Vec<crate::protocol::event_modules::types::EventRecord>,
    pub send_event_ids: Vec<EventId>,
}

pub fn start(context: &impl ReadContext, connection_id: EventId) -> Result<SyncReport, String> {
    // Manual start sends a full compare and, for the current simple protocol,
    // all have ids. The latter is intentionally easy to reason about and relies
    // on outbox idempotence rather than round state.
    let mut report = SyncReport::default();
    report
        .events
        .push(super::codec::outbound_record(CompareEvent {
            connection_id,
            summary: context.summary()?,
        })?);
    for event in all_have_items(context, connection_id)? {
        report.events.push(have_id::codec::outbound_record(event)?);
    }
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
        if context.can_send_event(&event.id)? {
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

fn all_have_items(
    context: &impl ReadContext,
    connection_id: EventId,
) -> Result<Vec<HaveIdEvent>, String> {
    let mut items = Vec::new();
    for bucket in 0..BUCKETS {
        let ids = context.ids_in_bucket(bucket as u8)?;
        for id in ids {
            items.push(HaveIdEvent {
                connection_id,
                bucket: bucket as u8,
                id,
            });
        }
    }
    Ok(items)
}

fn have_items_for_compare(
    context: &impl ReadContext,
    connection_id: EventId,
    local: [BucketSummary; BUCKETS],
    remote: [BucketSummary; BUCKETS],
) -> Result<Vec<HaveIdEvent>, String> {
    let mut items = Vec::new();
    for bucket in differing_buckets(&local, &remote) {
        let ids = context.ids_in_bucket(bucket)?;
        for id in ids {
            items.push(HaveIdEvent {
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

#[cfg(test)]
mod tests {
    use super::super::super::{have_id, need_id};
    use super::*;

    #[derive(Default)]
    struct Context {
        has_event: bool,
        can_send_event: bool,
    }

    impl ReadContext for Context {
        fn summary(&self) -> Result<[BucketSummary; BUCKETS], String> {
            Ok([BucketSummary::default(); BUCKETS])
        }

        fn ids_in_bucket(&self, _bucket: u8) -> Result<Vec<EventId>, String> {
            Ok(Vec::new())
        }

        fn has_event(&self, _event_id: &EventId) -> Result<bool, String> {
            Ok(self.has_event)
        }

        fn can_send_event(&self, _event_id: &EventId) -> Result<bool, String> {
            Ok(self.can_send_event)
        }
    }

    #[test]
    fn advertised_unknown_id_can_be_requested_before_it_is_servable_locally() {
        let connection_id = [1; 32];
        let wanted_id = [2; 32];
        let have = have_id::codec::outbound_record(have_id::types::HaveIdEvent {
            connection_id,
            bucket: 2,
            id: wanted_id,
        })
        .expect("have record");

        let report = handle_inbound_event(
            &Context {
                has_event: false,
                can_send_event: false,
            },
            connection_id,
            &have.canonical_bytes,
        )
        .expect("handle have");

        assert_eq!(report.events.len(), 1);
        let need = need_id::codec::decode(&report.events[0].canonical_bytes).expect("decode need");
        assert_eq!(need.connection_id, connection_id);
        assert_eq!(need.id, wanted_id);
    }

    #[test]
    fn requested_id_is_not_served_unless_connection_scope_allows_it() {
        let connection_id = [1; 32];
        let requested_id = [2; 32];
        let need = need_id::codec::outbound_record(need_id::types::NeedIdEvent {
            connection_id,
            id: requested_id,
        })
        .expect("need record");

        let denied = handle_inbound_event(
            &Context {
                has_event: true,
                can_send_event: false,
            },
            connection_id,
            &need.canonical_bytes,
        )
        .expect("handle denied need");
        assert!(denied.send_event_ids.is_empty());

        let allowed = handle_inbound_event(
            &Context {
                has_event: true,
                can_send_event: true,
            },
            connection_id,
            &need.canonical_bytes,
        )
        .expect("handle allowed need");
        assert_eq!(allowed.send_event_ids, vec![requested_id]);
    }
}
