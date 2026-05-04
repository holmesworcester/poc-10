use crux_core::{App, Command};

use super::commands::{
    connect, count, generate, generate_dependent_events, invite, replay_dependent_events_reverse,
    serve, sync_routes,
};
use super::effects::ProtocolEffect;
use super::model::{ProtocolModel, ProtocolMsg, ProtocolView};

#[derive(Debug, Default)]
pub struct ProtocolApp;

impl App for ProtocolApp {
    type Event = ProtocolMsg;
    type Model = ProtocolModel;
    type ViewModel = ProtocolView;
    type Effect = ProtocolEffect;

    fn update(
        &self,
        event: Self::Event,
        model: &mut Self::Model,
    ) -> Command<Self::Effect, Self::Event> {
        match event {
            ProtocolMsg::Failed(message) => {
                model.last_error = Some(message);
                Command::done()
            }
            ProtocolMsg::Invite { public_addr } => invite(public_addr),
            ProtocolMsg::InviteFinished(link) => {
                model.last_invite = Some(link);
                Command::done()
            }
            ProtocolMsg::Connect { invite } => connect(invite),
            ProtocolMsg::ConnectFinished(summary) => {
                model.last_connect = Some(summary);
                Command::done()
            }
            ProtocolMsg::SyncRoutes => sync_routes(),
            ProtocolMsg::SyncFinished(summary) => {
                model.last_sync = Some(summary);
                Command::done()
            }
            ProtocolMsg::Serve {
                listen,
                accept_count,
            } => serve(listen, accept_count),
            ProtocolMsg::ServeFinished(summary) => {
                model.last_serve = Some(summary);
                Command::done()
            }
            ProtocolMsg::Generate {
                num_events,
                event_size,
            } => generate(num_events, event_size),
            ProtocolMsg::GenerateFinished(summary) => {
                model.last_generate = Some(summary);
                Command::done()
            }
            ProtocolMsg::GenerateDependentEvents {
                num_events,
                deps_per_event,
            } => generate_dependent_events(num_events, deps_per_event),
            ProtocolMsg::GenerateDependentEventsFinished(summary) => {
                model.last_dependent_stage = Some(summary);
                Command::done()
            }
            ProtocolMsg::ReplayDependentEventsReverse => replay_dependent_events_reverse(),
            ProtocolMsg::ReplayDependentEventsReverseFinished(summary) => {
                model.last_dependent_replay = Some(summary);
                Command::done()
            }
            ProtocolMsg::Count => count(),
            ProtocolMsg::CountFinished(summary) => {
                model.last_count = Some(summary);
                Command::done()
            }
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        ProtocolView {
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
