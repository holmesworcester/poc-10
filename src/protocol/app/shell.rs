use std::collections::{HashMap, VecDeque};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};

use crux_core::{App, Command};

use crate::core::store::Store;
use crate::core::{control_loop, pipeline};
use crate::protocol::{inbound, Protocol};

use super::{
    ConnectionRequest, CountSummary, DependentReplaySummary, DependentStageSummary,
    DrainReadyReport, FrameIngest, GeneratedContent, NetworkOp, NetworkReply, OutboundSyncWork,
    ProtocolApp, ProtocolEffect, ProtocolModel, ProtocolMsg, StdoutOp, StdoutReply, StoreOp,
    StoreReply, SyncRoutesStart,
};

pub fn run_invite(
    store: &Store,
    protocol: &Protocol,
    public_addr: std::net::SocketAddr,
) -> Result<Vec<String>, String> {
    let app = ProtocolApp;
    let mut model = ProtocolModel::default();
    let mut shell = RealShell::new(store, protocol);
    shell.run(&app, &mut model, ProtocolMsg::Invite { public_addr })?;
    Ok(shell.stdout)
}

pub fn run_connect(
    store: &Store,
    protocol: &Protocol,
    invite: String,
) -> Result<Vec<String>, String> {
    let app = ProtocolApp;
    let mut model = ProtocolModel::default();
    let mut shell = RealShell::new(store, protocol);
    shell.run(&app, &mut model, ProtocolMsg::Connect { invite })?;
    if let Some(message) = model.last_error {
        return Err(message);
    }
    Ok(shell.stdout)
}

pub fn run_sync_routes(store: &Store, protocol: &Protocol) -> Result<Vec<String>, String> {
    let app = ProtocolApp;
    let mut model = ProtocolModel::default();
    let mut shell = RealShell::new(store, protocol);
    shell.run(&app, &mut model, ProtocolMsg::SyncRoutes)?;
    if let Some(message) = model.last_error {
        return Err(message);
    }
    Ok(shell.stdout)
}

pub fn run_serve(
    store: &Store,
    protocol: &Protocol,
    listen: SocketAddr,
    accept_count: usize,
) -> Result<Vec<String>, String> {
    let app = ProtocolApp;
    let mut model = ProtocolModel::default();
    let mut shell = RealShell::new(store, protocol);
    shell.run(
        &app,
        &mut model,
        ProtocolMsg::Serve {
            listen,
            accept_count,
        },
    )?;
    if let Some(message) = model.last_error {
        return Err(message);
    }
    Ok(shell.stdout)
}

pub fn run_generate(
    store: &Store,
    protocol: &Protocol,
    num_events: usize,
    event_size: usize,
) -> Result<Vec<String>, String> {
    let app = ProtocolApp;
    let mut model = ProtocolModel::default();
    let mut shell = RealShell::new(store, protocol);
    shell.run(
        &app,
        &mut model,
        ProtocolMsg::Generate {
            num_events,
            event_size,
        },
    )?;
    Ok(shell.stdout)
}

pub fn run_generate_dependent_events(
    store: &Store,
    protocol: &Protocol,
    num_events: usize,
    deps_per_event: usize,
) -> Result<Vec<String>, String> {
    let app = ProtocolApp;
    let mut model = ProtocolModel::default();
    let mut shell = RealShell::new(store, protocol);
    shell.run(
        &app,
        &mut model,
        ProtocolMsg::GenerateDependentEvents {
            num_events,
            deps_per_event,
        },
    )?;
    Ok(shell.stdout)
}

pub fn run_replay_dependent_events_reverse(
    store: &Store,
    protocol: &Protocol,
) -> Result<Vec<String>, String> {
    let app = ProtocolApp;
    let mut model = ProtocolModel::default();
    let mut shell = RealShell::new(store, protocol);
    shell.run(&app, &mut model, ProtocolMsg::ReplayDependentEventsReverse)?;
    Ok(shell.stdout)
}

pub fn run_count(store: &Store, protocol: &Protocol) -> Result<Vec<String>, String> {
    let app = ProtocolApp;
    let mut model = ProtocolModel::default();
    let mut shell = RealShell::new(store, protocol);
    shell.run(&app, &mut model, ProtocolMsg::Count)?;
    Ok(shell.stdout)
}

struct RealShell<'a> {
    store: &'a Store,
    protocol: &'a Protocol,
    listeners: HashMap<u64, TcpListener>,
    streams: HashMap<u64, TcpStream>,
    next_listener_id: u64,
    next_stream_id: u64,
    stdout: Vec<String>,
}

impl<'a> RealShell<'a> {
    fn new(store: &'a Store, protocol: &'a Protocol) -> Self {
        Self {
            store,
            protocol,
            listeners: HashMap::new(),
            streams: HashMap::new(),
            next_listener_id: 1,
            next_stream_id: 1,
            stdout: Vec::new(),
        }
    }

    fn run(
        &mut self,
        app: &ProtocolApp,
        model: &mut ProtocolModel,
        event: ProtocolMsg,
    ) -> Result<(), String> {
        let mut pending = VecDeque::from([event]);
        while let Some(event) = pending.pop_front() {
            let mut command = app.update(event, model);
            self.drain_command(&mut command, &mut pending)?;
        }
        Ok(())
    }

    fn drain_command(
        &mut self,
        command: &mut Command<ProtocolEffect, ProtocolMsg>,
        pending: &mut VecDeque<ProtocolMsg>,
    ) -> Result<(), String> {
        loop {
            let effects = command.effects().collect::<Vec<_>>();
            let events = command.events().collect::<Vec<_>>();
            let made_progress = !effects.is_empty() || !events.is_empty();

            for effect in effects {
                self.handle_effect(effect)?;
            }
            pending.extend(events);

            if command.is_done() {
                return Ok(());
            }
            if !made_progress {
                return Err("protocol command stalled".to_string());
            }
        }
    }

    fn handle_effect(&mut self, effect: ProtocolEffect) -> Result<(), String> {
        match effect {
            ProtocolEffect::Store(mut request) => {
                let reply = self.handle_store(request.operation.clone())?;
                request
                    .resolve(reply)
                    .map_err(|_| "store request was already resolved".to_string())
            }
            ProtocolEffect::Network(mut request) => {
                let reply = self.handle_network(request.operation.clone())?;
                request
                    .resolve(reply)
                    .map_err(|_| "network request was already resolved".to_string())
            }
            ProtocolEffect::Stdout(mut request) => {
                self.handle_stdout(request.operation.clone());
                request
                    .resolve(StdoutReply::Written)
                    .map_err(|_| "stdout request was already resolved".to_string())
            }
        }
    }

    fn handle_store(&self, operation: StoreOp) -> Result<StoreReply, String> {
        match operation {
            StoreOp::CreateInvite { public_addr } => {
                let output = self
                    .protocol
                    .modules()
                    .create_invite(self.store, public_addr)
                    .map_err(|err| format!("create invite: {err}"))?;
                let (link, _) = pipeline::run_command(self.store, self.protocol, output)
                    .map_err(|err| format!("apply invite: {err}"))?;
                Ok(StoreReply::InviteCreated { link })
            }
            StoreOp::CreateConnectionRequest { invite } => {
                let addr = self.protocol.modules().invite_addr(&invite)?;
                let output = self
                    .protocol
                    .modules()
                    .create_connection_request(self.store, &invite)?;
                let request = pipeline::run_command(self.store, self.protocol, output)
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
                let result = inbound::ingest_frame(
                    self.store,
                    self.protocol.modules(),
                    inbound::FrameMetadata {
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
                let (report, admitted) = pipeline::run_command(self.store, self.protocol, output)
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
                let (report, _) = pipeline::run_command(self.store, self.protocol, output)
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
                let (_, reverse_report) = pipeline::run_command(
                    self.store,
                    self.protocol.modules(),
                    crate::core::store::CommandOutput::with_events((), reverse_non_roots),
                )
                .map_err(|err| format!("admit reverse dependent events: {err}"))?;

                let blocked_after_reverse = self
                    .store
                    .status_counts()
                    .map_err(|err| format!("count blocked reverse events: {err}"))?
                    .blocked;

                let roots = records[..root_count].to_vec();
                let (_, root_report) = pipeline::run_command(
                    self.store,
                    self.protocol.modules(),
                    crate::core::store::CommandOutput::with_events((), roots),
                )
                .map_err(|err| format!("admit dependent roots: {err}"))?;
                let drain = control_loop::drain_until_idle(
                    self.store,
                    self.protocol.modules(),
                    control_loop::DEFAULT_READY_BATCH,
                )
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
                let report = control_loop::drain_until_idle(self.store, self.protocol, batch_size)
                    .map_err(|err| format!("drain generated events: {err}"))?;
                Ok(StoreReply::Drained(DrainReadyReport {
                    applied_events: report.applied_events,
                    unblocked_events: report.unblocked_events,
                }))
            }
            StoreOp::StartSyncRoutes => {
                control_loop::drain_until_idle(
                    self.store,
                    self.protocol.modules(),
                    control_loop::DEFAULT_READY_BATCH,
                )
                .map_err(|err| format!("drain ready events before sync: {err}"))?;

                let start = self
                    .protocol
                    .modules()
                    .start_sync(self.store)
                    .map_err(|err| format!("start sync: {err}"))?;
                let (started, _) = pipeline::run_command(self.store, self.protocol, start)
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

    fn handle_stdout(&mut self, operation: StdoutOp) {
        match operation {
            StdoutOp::PrintLines { lines } => self.stdout.extend(lines),
        }
    }

    fn handle_network(&mut self, operation: NetworkOp) -> Result<NetworkReply, String> {
        match operation {
            NetworkOp::BindListener { addr } => {
                let listener = TcpListener::bind(addr).map_err(|err| format!("listen: {err}"))?;
                let local_addr = listener
                    .local_addr()
                    .map_err(|err| format!("listener local addr: {err}"))?;
                let listener_id = self.next_listener_id;
                self.next_listener_id = self.next_listener_id.saturating_add(1);
                self.listeners.insert(listener_id, listener);
                Ok(NetworkReply::ListenerBound {
                    listener_id,
                    local_addr,
                })
            }
            NetworkOp::AcceptStream { listener_id } => {
                let listener = self
                    .listeners
                    .get(&listener_id)
                    .ok_or_else(|| format!("unknown listener id {listener_id}"))?;
                let (stream, peer_addr) = listener
                    .accept()
                    .map_err(|err| format!("accept tcp stream: {err}"))?;
                stream
                    .set_nodelay(true)
                    .map_err(|err| format!("set stream nodelay: {err}"))?;
                let stream_id = self.next_stream_id;
                self.next_stream_id = self.next_stream_id.saturating_add(1);
                self.streams.insert(stream_id, stream);
                Ok(NetworkReply::StreamAccepted {
                    stream_id,
                    peer_addr,
                })
            }
            NetworkOp::OpenStream { addr } => {
                let stream = crate::protocol::network::connect(addr)
                    .map_err(|err| format!("open tcp stream: {err}"))?;
                let stream_id = self.next_stream_id;
                self.next_stream_id = self.next_stream_id.saturating_add(1);
                self.streams.insert(stream_id, stream);
                Ok(NetworkReply::StreamOpened { stream_id })
            }
            NetworkOp::WriteFrames { stream_id, frames } => {
                let stream = self.stream(stream_id)?;
                crate::protocol::network::write_frames(stream, frames)?;
                Ok(NetworkReply::FramesWritten)
            }
            NetworkOp::ReadFrame { stream_id } => {
                let read = {
                    let stream = self.stream(stream_id)?;
                    crate::protocol::network::read_frame(stream)
                };
                match read {
                    Ok(bytes) => Ok(NetworkReply::FrameRead(bytes)),
                    Err(err) if is_stream_closed(&err) => {
                        self.streams.remove(&stream_id);
                        Ok(NetworkReply::StreamClosed)
                    }
                    Err(err) => Err(format!("read frame: {err}")),
                }
            }
            NetworkOp::ShutdownWrite { stream_id } => {
                let stream = self.stream(stream_id)?;
                stream
                    .shutdown(Shutdown::Write)
                    .map_err(|err| format!("shutdown stream write: {err}"))?;
                Ok(NetworkReply::WriteShutdown)
            }
        }
    }

    fn stream(&mut self, stream_id: u64) -> Result<&mut TcpStream, String> {
        self.streams
            .get_mut(&stream_id)
            .ok_or_else(|| format!("unknown stream id {stream_id}"))
    }
}

fn is_stream_closed(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
    )
}
