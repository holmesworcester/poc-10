use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};

use crate::core::crux_runner::{self, EffectHandler};
use crate::core::store::Store;
use crate::protocol::Protocol;

use super::{ProtocolApp, ProtocolEffect, ProtocolModel, ProtocolMsg, StdoutOp, StdoutReply};

pub fn run_invite(
    store: &Store,
    protocol: &Protocol,
    public_addr: std::net::SocketAddr,
) -> Result<Vec<String>, String> {
    run_message(store, protocol, ProtocolMsg::Invite { public_addr })
}

pub fn run_connect(
    store: &Store,
    protocol: &Protocol,
    invite: String,
) -> Result<Vec<String>, String> {
    run_message(store, protocol, ProtocolMsg::Connect { invite })
}

pub fn run_sync_routes(store: &Store, protocol: &Protocol) -> Result<Vec<String>, String> {
    run_message(store, protocol, ProtocolMsg::SyncRoutes)
}

pub fn run_serve(
    store: &Store,
    protocol: &Protocol,
    listen: SocketAddr,
    accept_count: usize,
) -> Result<Vec<String>, String> {
    run_message(
        store,
        protocol,
        ProtocolMsg::Serve {
            listen,
            accept_count,
        },
    )
}

pub fn run_generate(
    store: &Store,
    protocol: &Protocol,
    num_events: usize,
    event_size: usize,
) -> Result<Vec<String>, String> {
    run_message(
        store,
        protocol,
        ProtocolMsg::Generate {
            num_events,
            event_size,
        },
    )
}

pub fn run_generate_dependent_events(
    store: &Store,
    protocol: &Protocol,
    num_events: usize,
    deps_per_event: usize,
) -> Result<Vec<String>, String> {
    run_message(
        store,
        protocol,
        ProtocolMsg::GenerateDependentEvents {
            num_events,
            deps_per_event,
        },
    )
}

pub fn run_replay_dependent_events_reverse(
    store: &Store,
    protocol: &Protocol,
) -> Result<Vec<String>, String> {
    run_message(store, protocol, ProtocolMsg::ReplayDependentEventsReverse)
}

pub fn run_count(store: &Store, protocol: &Protocol) -> Result<Vec<String>, String> {
    run_message(store, protocol, ProtocolMsg::Count)
}

fn run_message(
    store: &Store,
    protocol: &Protocol,
    message: ProtocolMsg,
) -> Result<Vec<String>, String> {
    let app = ProtocolApp;
    let mut model = ProtocolModel::default();
    let mut shell = RealShell::new(store, protocol);
    crux_runner::run(&app, &mut model, message, &mut shell)?;
    if let Some(message) = model.last_error {
        return Err(message);
    }
    Ok(shell.into_stdout())
}

pub(super) struct RealShell<'a> {
    pub(super) store: &'a Store,
    pub(super) protocol: &'a Protocol,
    pub(super) listeners: HashMap<u64, TcpListener>,
    pub(super) streams: HashMap<u64, TcpStream>,
    pub(super) next_listener_id: u64,
    pub(super) next_stream_id: u64,
    pub(super) stdout: Vec<String>,
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

    fn into_stdout(self) -> Vec<String> {
        self.stdout
    }
}

impl EffectHandler<ProtocolEffect> for RealShell<'_> {
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
}

impl RealShell<'_> {
    fn handle_stdout(&mut self, operation: StdoutOp) {
        match operation {
            StdoutOp::PrintLines { lines } => self.stdout.extend(lines),
        }
    }
}
