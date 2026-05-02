use crux_core::{macros::effect, App, Command, Request};
use serde::{Deserialize, Serialize};

#[allow(deprecated)]
use crux_core::capability::Operation;

pub type PeerId = String;
pub type Version = u64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMessage {
    Hello {
        node_id: String,
        last_seen: Version,
    },
    Welcome {
        remote_version: Version,
    },
    SyncRequest {
        since: Version,
    },
    SyncBatch {
        changes: Vec<String>,
        complete: bool,
        remote_version: Version,
    },
    Ack {
        version: Version,
    },
    Error {
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkEvent {
    ConnectionOpened { peer: PeerId },
    ConnectionFailed { peer: PeerId, reason: String },
    Received { peer: PeerId, message: WireMessage },
    Disconnected { peer: PeerId, reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    Connect { peer: PeerId },
    Network(NetworkEvent),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MachineInput {
    Connect { peer: PeerId },
    ConnectionOpened { peer: PeerId },
    ConnectionFailed { peer: PeerId, reason: String },
    MessageReceived { peer: PeerId, message: WireMessage },
    Disconnected { peer: PeerId, reason: String },
}

impl From<Event> for MachineInput {
    fn from(event: Event) -> Self {
        match event {
            Event::Connect { peer } => MachineInput::Connect { peer },
            Event::Network(NetworkEvent::ConnectionOpened { peer }) => {
                MachineInput::ConnectionOpened { peer }
            }
            Event::Network(NetworkEvent::ConnectionFailed { peer, reason }) => {
                MachineInput::ConnectionFailed { peer, reason }
            }
            Event::Network(NetworkEvent::Received { peer, message }) => {
                MachineInput::MessageReceived { peer, message }
            }
            Event::Network(NetworkEvent::Disconnected { peer, reason }) => {
                MachineInput::Disconnected { peer, reason }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting {
        peer: PeerId,
    },
    Handshaking {
        peer: PeerId,
    },
    Syncing {
        peer: PeerId,
        requested_since: Version,
        remote_version: Version,
    },
    Connected {
        peer: PeerId,
        version: Version,
    },
    Failed {
        peer: Option<PeerId>,
        reason: String,
    },
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Disconnected
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkAction {
    OpenConnection { peer: PeerId },
    Send { peer: PeerId, message: WireMessage },
    Close { peer: PeerId, reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkOperation {
    OpenConnection { peer: PeerId },
    Send { peer: PeerId, message: WireMessage },
    Close { peer: PeerId, reason: String },
}

impl From<NetworkAction> for NetworkOperation {
    fn from(action: NetworkAction) -> Self {
        match action {
            NetworkAction::OpenConnection { peer } => Self::OpenConnection { peer },
            NetworkAction::Send { peer, message } => Self::Send { peer, message },
            NetworkAction::Close { peer, reason } => Self::Close { peer, reason },
        }
    }
}

impl Operation for NetworkOperation {
    type Output = ();
}

#[effect]
pub enum Effect {
    Network(NetworkOperation),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub state: ConnectionState,
    pub actions: Vec<NetworkAction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncStateMachine {
    state: ConnectionState,
    local_node_id: String,
    local_version: Version,
}

impl Default for SyncStateMachine {
    fn default() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            local_node_id: "local-node".to_string(),
            local_version: 0,
        }
    }
}

impl SyncStateMachine {
    pub fn new(local_node_id: impl Into<String>, local_version: Version) -> Self {
        Self {
            state: ConnectionState::Disconnected,
            local_node_id: local_node_id.into(),
            local_version,
        }
    }

    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    pub fn local_version(&self) -> Version {
        self.local_version
    }

    pub fn apply(&mut self, input: MachineInput) -> Transition {
        let actions = match input {
            MachineInput::Connect { peer } => self.connect(peer),
            MachineInput::ConnectionOpened { peer } => self.connection_opened(peer),
            MachineInput::ConnectionFailed { peer, reason } => self.fail(Some(peer), reason),
            MachineInput::MessageReceived { peer, message } => self.message_received(peer, message),
            MachineInput::Disconnected { peer: _, reason: _ } => {
                self.state = ConnectionState::Disconnected;
                Vec::new()
            }
        };

        Transition {
            state: self.state.clone(),
            actions,
        }
    }

    fn connect(&mut self, peer: PeerId) -> Vec<NetworkAction> {
        self.state = ConnectionState::Connecting { peer: peer.clone() };
        vec![NetworkAction::OpenConnection { peer }]
    }

    fn connection_opened(&mut self, peer: PeerId) -> Vec<NetworkAction> {
        if !matches_peer(&self.state, &peer) {
            return self.protocol_error(peer, "connection opened for unexpected peer");
        }

        self.state = ConnectionState::Handshaking { peer: peer.clone() };
        vec![NetworkAction::Send {
            peer,
            message: WireMessage::Hello {
                node_id: self.local_node_id.clone(),
                last_seen: self.local_version,
            },
        }]
    }

    fn message_received(&mut self, peer: PeerId, message: WireMessage) -> Vec<NetworkAction> {
        match (&self.state, message) {
            (
                ConnectionState::Handshaking { peer: expected },
                WireMessage::Welcome { remote_version },
            ) if expected == &peer => {
                self.state = ConnectionState::Syncing {
                    peer: peer.clone(),
                    requested_since: self.local_version,
                    remote_version,
                };

                vec![NetworkAction::Send {
                    peer,
                    message: WireMessage::SyncRequest {
                        since: self.local_version,
                    },
                }]
            }
            (
                ConnectionState::Syncing { peer: expected, .. },
                WireMessage::SyncBatch {
                    complete: true,
                    remote_version,
                    ..
                },
            ) if expected == &peer => {
                self.local_version = remote_version;
                self.state = ConnectionState::Connected {
                    peer: peer.clone(),
                    version: remote_version,
                };

                vec![NetworkAction::Send {
                    peer,
                    message: WireMessage::Ack {
                        version: remote_version,
                    },
                }]
            }
            (
                ConnectionState::Syncing { peer: expected, .. },
                WireMessage::SyncBatch {
                    complete: false, ..
                },
            ) if expected == &peer => Vec::new(),
            (_, WireMessage::Error { reason }) => self.fail(Some(peer), reason),
            _ => self.protocol_error(peer, "unexpected sync message for current state"),
        }
    }

    fn protocol_error(&mut self, peer: PeerId, reason: &str) -> Vec<NetworkAction> {
        let reason = reason.to_string();
        self.state = ConnectionState::Failed {
            peer: Some(peer.clone()),
            reason: reason.clone(),
        };
        vec![NetworkAction::Close { peer, reason }]
    }

    fn fail(&mut self, peer: Option<PeerId>, reason: String) -> Vec<NetworkAction> {
        self.state = ConnectionState::Failed {
            peer: peer.clone(),
            reason: reason.clone(),
        };

        match peer {
            Some(peer) => vec![NetworkAction::Close { peer, reason }],
            None => Vec::new(),
        }
    }
}

fn matches_peer(state: &ConnectionState, peer: &str) -> bool {
    match state {
        ConnectionState::Connecting { peer: expected }
        | ConnectionState::Handshaking { peer: expected }
        | ConnectionState::Syncing { peer: expected, .. }
        | ConnectionState::Connected { peer: expected, .. } => expected == peer,
        ConnectionState::Disconnected | ConnectionState::Failed { .. } => false,
    }
}

#[derive(Default)]
pub struct SyncApp;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Model {
    machine: SyncStateMachine,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewModel {
    pub state: ConnectionState,
    pub local_version: Version,
}

impl App for SyncApp {
    type Event = Event;
    type Model = Model;
    type ViewModel = ViewModel;
    type Effect = Effect;

    fn update(&self, event: Event, model: &mut Model) -> Command<Effect, Event> {
        let transition = model.machine.apply(event.into());
        network_command(transition.actions)
    }

    fn view(&self, model: &Model) -> Self::ViewModel {
        ViewModel {
            state: model.machine.state().clone(),
            local_version: model.machine.local_version(),
        }
    }
}

fn network_command(actions: Vec<NetworkAction>) -> Command<Effect, Event> {
    if actions.is_empty() {
        return Command::done();
    }

    let commands = actions
        .into_iter()
        .map(|action| {
            let operation = NetworkOperation::from(action);
            let command: Command<Effect, Event> = Command::notify_shell(operation).into();
            command
        })
        .collect::<Vec<_>>();

    Command::all(commands)
}

pub fn network_operations(effects: Vec<Effect>) -> Vec<NetworkOperation> {
    effects
        .into_iter()
        .map(|effect| match effect {
            Effect::Network(request) => request.operation,
        })
        .collect()
}

pub fn network_request(effect: Effect) -> Request<NetworkOperation> {
    match effect {
        Effect::Network(request) => request,
    }
}
