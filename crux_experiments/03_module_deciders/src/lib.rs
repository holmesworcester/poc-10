use crux_core::macros::effect;
use crux_core::{capability::Operation, App, Command};

pub mod module {
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct Projection {
        pub balance_cents: i64,
        pub applied_events: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum Command {
        Deposit { cents: u32 },
        Withdraw { cents: u32 },
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum CanonicalEvent {
        Deposited { cents: u32 },
        Withdrawn { cents: u32 },
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum Rejection {
        ZeroAmount,
        InsufficientFunds {
            requested_cents: u32,
            available_cents: i64,
        },
    }

    pub fn decide(
        projection: &Projection,
        command: &Command,
    ) -> Result<Vec<CanonicalEvent>, Rejection> {
        match command {
            Command::Deposit { cents: 0 } | Command::Withdraw { cents: 0 } => {
                Err(Rejection::ZeroAmount)
            }
            Command::Deposit { cents } => Ok(vec![CanonicalEvent::Deposited { cents: *cents }]),
            Command::Withdraw { cents } if projection.balance_cents >= i64::from(*cents) => {
                Ok(vec![CanonicalEvent::Withdrawn { cents: *cents }])
            }
            Command::Withdraw { cents } => Err(Rejection::InsufficientFunds {
                requested_cents: *cents,
                available_cents: projection.balance_cents,
            }),
        }
    }

    pub fn project(projection: &Projection, event: &CanonicalEvent) -> Projection {
        let balance_cents = match event {
            CanonicalEvent::Deposited { cents } => projection.balance_cents + i64::from(*cents),
            CanonicalEvent::Withdrawn { cents } => projection.balance_cents - i64::from(*cents),
        };

        Projection {
            balance_cents,
            applied_events: projection.applied_events + 1,
        }
    }

    pub fn project_all<'a>(
        projection: &Projection,
        events: impl IntoIterator<Item = &'a CanonicalEvent>,
    ) -> Projection {
        events
            .into_iter()
            .fold(projection.clone(), |next, event| project(&next, event))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    Submit(module::Command),
    AdmissionCompleted(AdmissionOutcome),
    ApplyCompleted(ApplyReceipt),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionOperation {
    pub command: module::Command,
    pub candidate_events: Vec<module::CanonicalEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionOutcome {
    Accepted { events: Vec<module::CanonicalEvent> },
    Rejected { reason: String },
}

impl Operation for AdmissionOperation {
    type Output = AdmissionOutcome;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyOperation {
    pub events: Vec<module::CanonicalEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyReceipt {
    pub applied_events: u64,
}

impl Operation for ApplyOperation {
    type Output = ApplyReceipt;
}

#[effect]
pub enum Effect {
    Admission(AdmissionOperation),
    Apply(ApplyOperation),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Model {
    pub projection: module::Projection,
    pub last_rejection: Option<module::Rejection>,
    pub last_admission_rejection: Option<String>,
    pub last_apply_receipt: Option<ApplyReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewModel {
    pub balance_cents: i64,
    pub applied_events: u64,
    pub last_rejection: Option<module::Rejection>,
    pub last_admission_rejection: Option<String>,
    pub last_apply_receipt: Option<ApplyReceipt>,
}

#[derive(Default)]
pub struct LedgerApp;

impl App for LedgerApp {
    type Event = Message;
    type Model = Model;
    type ViewModel = ViewModel;
    type Effect = Effect;

    fn update(&self, event: Message, model: &mut Model) -> Command<Effect, Message> {
        match event {
            Message::Submit(command) => match module::decide(&model.projection, &command) {
                Ok(candidate_events) => {
                    model.last_rejection = None;
                    model.last_admission_rejection = None;
                    model.last_apply_receipt = None;

                    Command::request_from_shell(AdmissionOperation {
                        command,
                        candidate_events,
                    })
                    .then_send(Message::AdmissionCompleted)
                }
                Err(rejection) => {
                    model.last_rejection = Some(rejection);
                    Command::done()
                }
            },
            Message::AdmissionCompleted(AdmissionOutcome::Accepted { events }) => {
                model.projection = module::project_all(&model.projection, &events);
                model.last_admission_rejection = None;

                Command::request_from_shell(ApplyOperation { events })
                    .then_send(Message::ApplyCompleted)
            }
            Message::AdmissionCompleted(AdmissionOutcome::Rejected { reason }) => {
                model.last_admission_rejection = Some(reason);
                Command::done()
            }
            Message::ApplyCompleted(receipt) => {
                model.last_apply_receipt = Some(receipt);
                Command::done()
            }
        }
    }

    fn view(&self, model: &Model) -> ViewModel {
        ViewModel {
            balance_cents: model.projection.balance_cents,
            applied_events: model.projection.applied_events,
            last_rejection: model.last_rejection.clone(),
            last_admission_rejection: model.last_admission_rejection.clone(),
            last_apply_receipt: model.last_apply_receipt.clone(),
        }
    }
}
