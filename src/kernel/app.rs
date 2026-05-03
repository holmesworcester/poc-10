use crux_core::{App, Command};

use super::commands::{
    connect, count, generate, generate_dependent_events, invite, replay_dependent_events_reverse,
    serve, sync_routes,
};
use super::effects::KernelEffect;
use super::model::{KernelModel, KernelMsg, KernelView};

#[derive(Debug, Default)]
pub struct KernelApp;

impl App for KernelApp {
    type Event = KernelMsg;
    type Model = KernelModel;
    type ViewModel = KernelView;
    type Effect = KernelEffect;

    fn update(
        &self,
        event: Self::Event,
        model: &mut Self::Model,
    ) -> Command<Self::Effect, Self::Event> {
        match event {
            KernelMsg::Failed(message) => {
                model.last_error = Some(message);
                Command::done()
            }
            KernelMsg::Invite { public_addr } => invite(public_addr),
            KernelMsg::InviteFinished(link) => {
                model.last_invite = Some(link);
                Command::done()
            }
            KernelMsg::Connect { invite } => connect(invite),
            KernelMsg::ConnectFinished(summary) => {
                model.last_connect = Some(summary);
                Command::done()
            }
            KernelMsg::SyncRoutes => sync_routes(),
            KernelMsg::SyncFinished(summary) => {
                model.last_sync = Some(summary);
                Command::done()
            }
            KernelMsg::Serve {
                listen,
                accept_count,
            } => serve(listen, accept_count),
            KernelMsg::ServeFinished(summary) => {
                model.last_serve = Some(summary);
                Command::done()
            }
            KernelMsg::Generate {
                num_events,
                event_size,
            } => generate(num_events, event_size),
            KernelMsg::GenerateFinished(summary) => {
                model.last_generate = Some(summary);
                Command::done()
            }
            KernelMsg::GenerateDependentEvents {
                num_events,
                deps_per_event,
            } => generate_dependent_events(num_events, deps_per_event),
            KernelMsg::GenerateDependentEventsFinished(summary) => {
                model.last_dependent_stage = Some(summary);
                Command::done()
            }
            KernelMsg::ReplayDependentEventsReverse => replay_dependent_events_reverse(),
            KernelMsg::ReplayDependentEventsReverseFinished(summary) => {
                model.last_dependent_replay = Some(summary);
                Command::done()
            }
            KernelMsg::Count => count(),
            KernelMsg::CountFinished(summary) => {
                model.last_count = Some(summary);
                Command::done()
            }
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        KernelView {
            last_error: model.last_error.clone(),
            last_invite: model.last_invite.clone(),
            last_connect: model.last_connect.clone(),
            last_sync: model.last_sync.clone(),
            last_serve: model.last_serve.clone(),
            last_generate: model.last_generate.clone(),
            last_dependent_stage: model.last_dependent_stage.clone(),
            last_dependent_replay: model.last_dependent_replay.clone(),
            last_count: model.last_count.clone(),
        }
    }
}
