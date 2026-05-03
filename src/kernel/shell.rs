use std::collections::VecDeque;

use crux_core::{App, Command};

use crate::event_modules::Modules;
use crate::store::Store;
use crate::{control_loop, pipeline};

use super::app::{
    CountSummary, DrainReadyReport, GeneratedContent, KernelApp, KernelEffect, KernelModel,
    KernelMsg, StdoutOp, StdoutReply, StoreOp, StoreReply,
};

pub fn run_invite(
    store: &Store,
    modules: &Modules,
    public_addr: std::net::SocketAddr,
) -> Result<Vec<String>, String> {
    let app = KernelApp;
    let mut model = KernelModel::default();
    let mut shell = RealShell {
        store,
        modules,
        stdout: Vec::new(),
    };
    shell.run(&app, &mut model, KernelMsg::Invite { public_addr })?;
    Ok(shell.stdout)
}

pub fn run_generate(
    store: &Store,
    modules: &Modules,
    num_events: usize,
    event_size: usize,
) -> Result<Vec<String>, String> {
    let app = KernelApp;
    let mut model = KernelModel::default();
    let mut shell = RealShell {
        store,
        modules,
        stdout: Vec::new(),
    };
    shell.run(
        &app,
        &mut model,
        KernelMsg::Generate {
            num_events,
            event_size,
        },
    )?;
    Ok(shell.stdout)
}

pub fn run_count(store: &Store, modules: &Modules) -> Result<Vec<String>, String> {
    let app = KernelApp;
    let mut model = KernelModel::default();
    let mut shell = RealShell {
        store,
        modules,
        stdout: Vec::new(),
    };
    shell.run(&app, &mut model, KernelMsg::Count)?;
    Ok(shell.stdout)
}

struct RealShell<'a> {
    store: &'a Store,
    modules: &'a Modules,
    stdout: Vec<String>,
}

impl RealShell<'_> {
    fn run(
        &mut self,
        app: &KernelApp,
        model: &mut KernelModel,
        event: KernelMsg,
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
        command: &mut Command<KernelEffect, KernelMsg>,
        pending: &mut VecDeque<KernelMsg>,
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
                return Err("kernel command stalled".to_string());
            }
        }
    }

    fn handle_effect(&mut self, effect: KernelEffect) -> Result<(), String> {
        match effect {
            KernelEffect::Store(mut request) => {
                let reply = self.handle_store(request.operation.clone())?;
                request
                    .resolve(reply)
                    .map_err(|_| "store request was already resolved".to_string())
            }
            KernelEffect::Stdout(mut request) => {
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
                    .modules
                    .create_invite(self.store, public_addr)
                    .map_err(|err| format!("create invite: {err}"))?;
                let (link, _) = pipeline::run_command(self.store, self.modules, output)
                    .map_err(|err| format!("apply invite: {err}"))?;
                Ok(StoreReply::InviteCreated { link })
            }
            StoreOp::GenerateContent {
                num_events,
                event_size,
            } => {
                let output = self
                    .modules
                    .generate_content(self.store, num_events, event_size)
                    .map_err(|err| format!("generate: {err}"))?;
                let (report, admitted) = pipeline::run_command(self.store, self.modules, output)
                    .map_err(|err| format!("admit generated events: {err}"))?;
                Ok(StoreReply::Generated(GeneratedContent {
                    inserted_events: admitted.inserted_events,
                    applied_events: admitted.applied_events,
                    event_size,
                    first_timestamp: report.first_timestamp,
                    last_timestamp: report.last_timestamp,
                }))
            }
            StoreOp::DrainReadyUntilIdle { batch_size } => {
                let report = control_loop::drain_until_idle(self.store, self.modules, batch_size)
                    .map_err(|err| format!("drain generated events: {err}"))?;
                Ok(StoreReply::Drained(DrainReadyReport {
                    applied_events: report.applied_events,
                    unblocked_events: report.unblocked_events,
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
                let connections = self.modules.connection_count(self.store)?;
                let connection_events = self.modules.connection_event_count(self.store)?;
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
}
