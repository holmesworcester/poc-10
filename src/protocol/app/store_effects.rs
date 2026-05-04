use crate::protocol::event_modules::worker::{self, CommandOutput, Worker};

use super::effects::{
    ConnectionRequest, DrainReadyReport, FrameIngest, GeneratedContent, OutboundSyncWork, StoreOp,
    StoreReply, SyncRoutesStart,
};
use super::shell::RealShell;
use super::summaries::{CountSummary, DependentReplaySummary, DependentStageSummary};

impl RealShell<'_> {
    pub(super) fn handle_store(&self, operation: StoreOp) -> Result<StoreReply, String> {
        match operation {
            StoreOp::CreateInvite { public_addr } => {
                let output = self
                    .protocol
                    .modules()
                    .create_invite(self.store, public_addr)
                    .map_err(|err| format!("create invite: {err}"))?;
                let (link, _) = Worker::new(self.store, self.protocol)
                    .run_command(output)
                    .map_err(|err| format!("apply invite: {err}"))?;
                Ok(StoreReply::InviteCreated { link })
            }
            StoreOp::CreateConnectionRequest { invite } => {
                let addr = self.protocol.modules().invite_addr(&invite)?;
                let output = self
                    .protocol
                    .modules()
                    .create_connection_request(self.store, &invite)?;
                let request = Worker::new(self.store, self.protocol)
                    .run_command(output)
                    .map_err(|err| format!("record connection request: {err}"))?
                    .0;
                Ok(StoreReply::ConnectionRequestCreated(ConnectionRequest {
                    addr,
                    bytes: request.bytes,
                }))
            }
            StoreOp::IngestFrame {
                origin,
                remember_origin,
                bytes,
            } => {
                let result = worker::ingest_frame(
                    self.store,
                    self.protocol.modules(),
                    worker::FrameMetadata {
                        origin,
                        remember_origin,
                    },
                    bytes,
                )?;
                Ok(StoreReply::FrameIngested(FrameIngest {
                    outgoing: result.outgoing,
                    sent_outbox: result.sent_outbox,
                    established_routes: result.established_routes,
                    sent_events: result.sent_events,
                    received_events: result.received_events,
                }))
            }
            StoreOp::MarkOutboxSent { sent_outbox } => {
                self.protocol
                    .modules()
                    .mark_outbox_sent(self.store, sent_outbox)?;
                Ok(StoreReply::OutboxMarked)
            }
            StoreOp::GenerateContent {
                num_events,
                event_size,
            } => {
                let output = self
                    .protocol
                    .modules()
                    .generate_content(self.store, num_events, event_size)
                    .map_err(|err| format!("generate: {err}"))?;
                let (report, admitted) = Worker::new(self.store, self.protocol)
                    .run_command(output)
                    .map_err(|err| format!("admit generated events: {err}"))?;
                Ok(StoreReply::Generated(GeneratedContent {
                    inserted_events: admitted.inserted_events,
                    applied_events: admitted.applied_events,
                    event_size,
                    first_timestamp: report.first_timestamp,
                    last_timestamp: report.last_timestamp,
                }))
            }
            StoreOp::StageDependentEvents {
                num_events,
                deps_per_event,
            } => {
                let output = self
                    .protocol
                    .modules()
                    .stage_dependent_events(self.store, num_events, deps_per_event)
                    .map_err(|err| format!("stage dependent events: {err}"))?;
                let (report, _) = Worker::new(self.store, self.protocol)
                    .run_command(output)
                    .map_err(|err| format!("admit staged dependent events: {err}"))?;
                Ok(StoreReply::DependentEventsStaged(DependentStageSummary {
                    staged_events: report.staged_events,
                    deps_per_event: report.deps_per_event,
                    dep_edges: report.dep_edges,
                    first_timestamp: report.first_timestamp,
                    last_timestamp: report.last_timestamp,
                }))
            }
            StoreOp::ReplayDependentEventsReverse => {
                let records = self
                    .protocol
                    .modules()
                    .staged_dependent_records(self.store)
                    .map_err(|err| format!("load staged dependent events: {err}"))?;
                if records.is_empty() {
                    return Err("no staged dependent events to replay".to_string());
                }

                let max_deps = records
                    .iter()
                    .map(|record| record.dependencies.len())
                    .max()
                    .unwrap_or(0);
                let root_count = records.len().min(max_deps.max(1));
                let reverse_non_roots = records[root_count..].iter().rev().cloned().collect();
                let (_, reverse_report) = Worker::new(self.store, self.protocol.modules())
                    .run_command(CommandOutput::with_events((), reverse_non_roots))
                    .map_err(|err| format!("admit reverse dependent events: {err}"))?;

                let blocked_after_reverse = self
                    .store
                    .status_counts()
                    .map_err(|err| format!("count blocked reverse events: {err}"))?
                    .blocked;

                let roots = records[..root_count].to_vec();
                let (_, root_report) = Worker::new(self.store, self.protocol.modules())
                    .run_command(CommandOutput::with_events((), roots))
                    .map_err(|err| format!("admit dependent roots: {err}"))?;
                let drain = Worker::new(self.store, self.protocol.modules())
                    .drain_until_idle(worker::DEFAULT_READY_BATCH)
                    .map_err(|err| format!("drain dependent replay: {err}"))?;
                let final_counts = self
                    .store
                    .status_counts()
                    .map_err(|err| format!("count dependent replay statuses: {err}"))?;

                Ok(StoreReply::DependentEventsReplayed(
                    DependentReplaySummary {
                        replayed_events: records.len(),
                        blocked_after_reverse,
                        applied_events: reverse_report.applied_events
                            + root_report.applied_events
                            + drain.applied_events,
                        ready_events: final_counts.ready,
                        blocked_events: final_counts.blocked,
                        blocked_edges: final_counts.blocked_edges,
                    },
                ))
            }
            StoreOp::DrainReadyUntilIdle { batch_size } => {
                let report = Worker::new(self.store, self.protocol)
                    .drain_until_idle(batch_size)
                    .map_err(|err| format!("drain generated events: {err}"))?;
                Ok(StoreReply::Drained(DrainReadyReport {
                    applied_events: report.applied_events,
                    unblocked_events: report.unblocked_events,
                }))
            }
            StoreOp::StartSyncRoutes => {
                Worker::new(self.store, self.protocol.modules())
                    .drain_until_idle(worker::DEFAULT_READY_BATCH)
                    .map_err(|err| format!("drain ready events before sync: {err}"))?;

                let start = self
                    .protocol
                    .modules()
                    .start_sync(self.store)
                    .map_err(|err| format!("start sync: {err}"))?;
                let (started, _) = Worker::new(self.store, self.protocol)
                    .run_command(start)
                    .map_err(|err| format!("record sync frames: {err}"))?;
                let outbound = self
                    .protocol
                    .modules()
                    .drain_outbox_routes(self.store)
                    .map_err(|err| format!("drain sync outbox: {err}"))?
                    .into_iter()
                    .map(|outbound| OutboundSyncWork {
                        target: outbound.target,
                        outgoing: outbound.outgoing,
                        sent_outbox: outbound.sent_outbox,
                        sent_events: outbound.sent_events,
                    })
                    .collect();
                Ok(StoreReply::SyncStarted(SyncRoutesStart {
                    outbound,
                    sent_events: started.sent_events,
                }))
            }
            StoreOp::CountStatus => {
                let events = self
                    .store
                    .event_count()
                    .map_err(|err| format!("count events: {err}"))?;
                let payload_bytes = self
                    .store
                    .body_bytes()
                    .map_err(|err| format!("count bytes: {err}"))?;
                let connections = self.protocol.modules().connection_count(self.store)?;
                let connection_events =
                    self.protocol.modules().connection_event_count(self.store)?;
                let statuses = self
                    .store
                    .status_counts()
                    .map_err(|err| format!("count event statuses: {err}"))?;
                Ok(StoreReply::Counted(CountSummary {
                    events,
                    payload_bytes,
                    connections,
                    connection_events,
                    ready_events: statuses.ready,
                    blocked_events: statuses.blocked,
                    applied_events: statuses.applied,
                    rejected_events: statuses.rejected,
                    blocked_edges: statuses.blocked_edges,
                }))
            }
        }
    }
}
