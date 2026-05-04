use std::net::SocketAddr;

use crux_core::{command::CommandContext, Command};

use crate::core::control_loop;

use super::effects::{
    NetworkOp, NetworkReply, ProtocolEffect, StdoutOp, StdoutReply, StoreOp, StoreReply,
};
use super::model::ProtocolMsg;
use super::summaries::{ConnectSummary, GenerateSummary, ServeSummary, StreamSummary, SyncSummary};

pub(super) fn invite(public_addr: SocketAddr) -> Command<ProtocolEffect, ProtocolMsg> {
    Command::new(|ctx| async move {
        let link = match ctx
            .request_from_shell(StoreOp::CreateInvite { public_addr })
            .await
        {
            StoreReply::InviteCreated { link } => link,
            _ => panic!("invite received non-invite store reply"),
        };

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: vec![link.clone()],
            })
            .await
        {
            StdoutReply::Written => {}
        }

        ctx.send_event(ProtocolMsg::InviteFinished(link));
    })
}

pub(super) fn connect(invite: String) -> Command<ProtocolEffect, ProtocolMsg> {
    Command::new(|ctx| async move {
        let request = match ctx
            .request_from_shell(StoreOp::CreateConnectionRequest { invite })
            .await
        {
            StoreReply::ConnectionRequestCreated(request) => request,
            _ => panic!("connect received non-connection-request store reply"),
        };

        let stream_id = match ctx
            .request_from_shell(NetworkOp::OpenStream { addr: request.addr })
            .await
        {
            NetworkReply::StreamOpened { stream_id } => stream_id,
            _ => panic!("open stream returned non-open reply"),
        };

        match ctx
            .request_from_shell(NetworkOp::WriteFrames {
                stream_id,
                frames: vec![request.bytes],
            })
            .await
        {
            NetworkReply::FramesWritten => {}
            _ => panic!("write frames returned non-write reply"),
        }

        let stream = pump_stream(&ctx, stream_id, request.addr, true).await;

        if stream.established_routes == 0 {
            ctx.send_event(ProtocolMsg::Failed(
                "connection was not established".to_string(),
            ));
            return;
        }

        let summary = ConnectSummary {
            addr: request.addr,
            established_routes: stream.established_routes,
        };
        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: vec![format!("connected: {}", summary.addr)],
            })
            .await
        {
            StdoutReply::Written => {}
        }
        ctx.send_event(ProtocolMsg::ConnectFinished(summary));
    })
}

pub(super) fn sync_routes() -> Command<ProtocolEffect, ProtocolMsg> {
    Command::new(|ctx| async move {
        let start = match ctx.request_from_shell(StoreOp::StartSyncRoutes).await {
            StoreReply::SyncStarted(start) => start,
            _ => panic!("sync received non-sync-start store reply"),
        };

        let mut summary = SyncSummary {
            sent_events: start.sent_events,
            ..SyncSummary::default()
        };

        for outbound in start.outbound {
            let stream_id = match ctx
                .request_from_shell(NetworkOp::OpenStream {
                    addr: outbound.target,
                })
                .await
            {
                NetworkReply::StreamOpened { stream_id } => stream_id,
                _ => panic!("open stream returned non-open reply"),
            };

            match ctx
                .request_from_shell(NetworkOp::WriteFrames {
                    stream_id,
                    frames: outbound.outgoing,
                })
                .await
            {
                NetworkReply::FramesWritten => {}
                _ => panic!("write sync frames returned non-write reply"),
            }

            match ctx
                .request_from_shell(StoreOp::MarkOutboxSent {
                    sent_outbox: outbound.sent_outbox,
                })
                .await
            {
                StoreReply::OutboxMarked => {}
                _ => panic!("mark sync outbox returned non-mark reply"),
            }

            let stream = pump_stream(&ctx, stream_id, outbound.target, false).await;
            summary.routes_synced += 1;
            summary.sent_events += outbound.sent_events + stream.sent_events;
            summary.received_events += stream.received_events;
        }

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: summary.lines(),
            })
            .await
        {
            StdoutReply::Written => {}
        }
        ctx.send_event(ProtocolMsg::SyncFinished(summary));
    })
}

pub(super) fn serve(
    listen: SocketAddr,
    accept_count: usize,
) -> Command<ProtocolEffect, ProtocolMsg> {
    Command::new(|ctx| async move {
        let (listener_id, local_addr) = match ctx
            .request_from_shell(NetworkOp::BindListener { addr: listen })
            .await
        {
            NetworkReply::ListenerBound {
                listener_id,
                local_addr,
            } => (listener_id, local_addr),
            _ => panic!("bind listener returned non-listener reply"),
        };

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: vec![format!("listening: {local_addr}")],
            })
            .await
        {
            StdoutReply::Written => {}
        }

        let mut summary = ServeSummary::default();
        for _ in 0..accept_count {
            let (stream_id, peer_addr) = match ctx
                .request_from_shell(NetworkOp::AcceptStream { listener_id })
                .await
            {
                NetworkReply::StreamAccepted {
                    stream_id,
                    peer_addr,
                } => (stream_id, peer_addr),
                _ => panic!("accept stream returned non-accept reply"),
            };
            let stream = pump_stream(&ctx, stream_id, peer_addr, false).await;
            summary.accepted_connections += 1;
            summary.received_events += stream.received_events;
        }

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: summary.lines(),
            })
            .await
        {
            StdoutReply::Written => {}
        }
        ctx.send_event(ProtocolMsg::ServeFinished(summary));
    })
}

async fn pump_stream(
    ctx: &CommandContext<ProtocolEffect, ProtocolMsg>,
    stream_id: u64,
    origin: SocketAddr,
    remember_origin: bool,
) -> StreamSummary {
    let mut summary = StreamSummary::default();
    let mut write_open = true;
    loop {
        let bytes = match ctx
            .request_from_shell(NetworkOp::ReadFrame { stream_id })
            .await
        {
            NetworkReply::FrameRead(bytes) => bytes,
            NetworkReply::StreamClosed => break,
            _ => panic!("read frame returned non-read reply"),
        };

        let ingest = match ctx
            .request_from_shell(StoreOp::IngestFrame {
                origin,
                remember_origin,
                bytes,
            })
            .await
        {
            StoreReply::FrameIngested(ingest) => ingest,
            _ => panic!("ingest frame returned non-ingest reply"),
        };
        summary.established_routes += ingest.established_routes;
        summary.sent_events += ingest.sent_events;
        summary.received_events += ingest.received_events;

        match ctx
            .request_from_shell(StoreOp::DrainReadyUntilIdle {
                batch_size: control_loop::DEFAULT_READY_BATCH,
            })
            .await
        {
            StoreReply::Drained(_) => {}
            _ => panic!("stream drain returned non-drain reply"),
        }

        if ingest.outgoing.is_empty() {
            if write_open {
                match ctx
                    .request_from_shell(NetworkOp::ShutdownWrite { stream_id })
                    .await
                {
                    NetworkReply::WriteShutdown => {}
                    _ => panic!("shutdown write returned non-shutdown reply"),
                }
                write_open = false;
            }
        } else {
            match ctx
                .request_from_shell(NetworkOp::WriteFrames {
                    stream_id,
                    frames: ingest.outgoing,
                })
                .await
            {
                NetworkReply::FramesWritten => {}
                _ => panic!("write response frames returned non-write reply"),
            }
            match ctx
                .request_from_shell(StoreOp::MarkOutboxSent {
                    sent_outbox: ingest.sent_outbox,
                })
                .await
            {
                StoreReply::OutboxMarked => {}
                _ => panic!("mark outbox returned non-mark reply"),
            }
        }
    }
    summary
}

pub(super) fn generate(
    num_events: usize,
    event_size: usize,
) -> Command<ProtocolEffect, ProtocolMsg> {
    Command::new(|ctx| async move {
        let generated = match ctx
            .request_from_shell(StoreOp::GenerateContent {
                num_events,
                event_size,
            })
            .await
        {
            StoreReply::Generated(generated) => generated,
            _ => panic!("generate received non-generate store reply"),
        };

        let drained = match ctx
            .request_from_shell(StoreOp::DrainReadyUntilIdle {
                batch_size: control_loop::DEFAULT_READY_BATCH,
            })
            .await
        {
            StoreReply::Drained(drained) => drained,
            _ => panic!("drain received non-drain store reply"),
        };

        let summary = GenerateSummary {
            generated_events: generated.inserted_events,
            applied_events: generated.applied_events + drained.applied_events,
            event_size: generated.event_size,
            first_timestamp: generated.first_timestamp,
            last_timestamp: generated.last_timestamp,
        };

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: summary.lines(),
            })
            .await
        {
            StdoutReply::Written => {}
        }

        ctx.send_event(ProtocolMsg::GenerateFinished(summary));
    })
}

pub(super) fn generate_dependent_events(
    num_events: usize,
    deps_per_event: usize,
) -> Command<ProtocolEffect, ProtocolMsg> {
    Command::new(|ctx| async move {
        let summary = match ctx
            .request_from_shell(StoreOp::StageDependentEvents {
                num_events,
                deps_per_event,
            })
            .await
        {
            StoreReply::DependentEventsStaged(summary) => summary,
            _ => panic!("generate deps received non-stage store reply"),
        };

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: summary.lines(),
            })
            .await
        {
            StdoutReply::Written => {}
        }

        ctx.send_event(ProtocolMsg::GenerateDependentEventsFinished(summary));
    })
}

pub(super) fn replay_dependent_events_reverse() -> Command<ProtocolEffect, ProtocolMsg> {
    Command::new(|ctx| async move {
        let summary = match ctx
            .request_from_shell(StoreOp::ReplayDependentEventsReverse)
            .await
        {
            StoreReply::DependentEventsReplayed(summary) => summary,
            _ => panic!("replay deps received non-replay store reply"),
        };

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: summary.lines(),
            })
            .await
        {
            StdoutReply::Written => {}
        }

        ctx.send_event(ProtocolMsg::ReplayDependentEventsReverseFinished(summary));
    })
}

pub(super) fn count() -> Command<ProtocolEffect, ProtocolMsg> {
    Command::new(|ctx| async move {
        let summary = match ctx.request_from_shell(StoreOp::CountStatus).await {
            StoreReply::Counted(summary) => summary,
            _ => panic!("count received non-count store reply"),
        };

        match ctx
            .request_from_shell(StdoutOp::PrintLines {
                lines: summary.lines(),
            })
            .await
        {
            StdoutReply::Written => {}
        }

        ctx.send_event(ProtocolMsg::CountFinished(summary));
    })
}
