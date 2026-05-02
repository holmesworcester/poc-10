use crux_core::capability::Operation;
use crux_core::macros::effect;
use crux_core::{App, Command};
use serde::{Deserialize, Serialize};

pub const DEFAULT_READY_BATCH: usize = 4096;

#[derive(Default)]
pub struct PipelineFacade;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    Generate {
        records: usize,
        payload_bytes: usize,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Model {
    pub next_batch_id: u64,
    pub requested_records: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewModel {
    pub next_batch_id: u64,
    pub requested_records: usize,
}

#[effect]
pub enum Effect {
    Store(StoreRecords),
    Drain(DrainReady),
    Print(PrintReport),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticRecord {
    pub batch_id: u64,
    pub ordinal: usize,
    pub payload_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreRecords {
    pub batch_id: u64,
    pub records: Vec<SyntheticRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreReport {
    pub inserted_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
}

impl Operation for StoreRecords {
    type Output = StoreReport;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainReady {
    pub batch_id: u64,
    pub batch_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainReport {
    pub applied_events: usize,
    pub unblocked_events: usize,
}

impl Operation for DrainReady {
    type Output = DrainReport;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintReport {
    pub batch_id: u64,
    pub lines: Vec<String>,
}

impl Operation for PrintReport {
    type Output = ();
}

impl App for PipelineFacade {
    type Event = Event;
    type Model = Model;
    type ViewModel = ViewModel;
    type Effect = Effect;

    fn update(&self, event: Self::Event, model: &mut Self::Model) -> Command<Effect, Event> {
        match event {
            Event::Generate {
                records,
                payload_bytes,
            } => {
                let batch_id = model.next_batch_id;
                model.next_batch_id += 1;
                model.requested_records += records;

                let records = (0..records)
                    .map(|ordinal| SyntheticRecord {
                        batch_id,
                        ordinal,
                        payload_bytes,
                    })
                    .collect();

                Command::new(move |ctx| async move {
                    let stored = ctx
                        .request_from_shell(StoreRecords { batch_id, records })
                        .await;
                    let drained = ctx
                        .request_from_shell(DrainReady {
                            batch_id,
                            batch_size: DEFAULT_READY_BATCH,
                        })
                        .await;

                    ctx.notify_shell(PrintReport {
                        batch_id,
                        lines: summary_lines(stored, drained, payload_bytes),
                    });
                })
            }
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        ViewModel {
            next_batch_id: model.next_batch_id,
            requested_records: model.requested_records,
        }
    }
}

fn summary_lines(stored: StoreReport, drained: DrainReport, payload_bytes: usize) -> Vec<String> {
    vec![
        format!("generated_events: {}", stored.inserted_events),
        format!("ready_events: {}", stored.ready_events),
        format!("blocked_events: {}", stored.blocked_events),
        format!("applied_events: {}", drained.applied_events),
        format!("unblocked_events: {}", drained.unblocked_events),
        format!("event_size_bytes: {payload_bytes}"),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoRun {
    pub effect_order: Vec<&'static str>,
    pub printed: Vec<String>,
    pub view: ViewModel,
}

pub fn run_demo_shell(records: usize, payload_bytes: usize) -> DemoRun {
    let app = PipelineFacade;
    let mut model = Model::default();
    let mut cmd = app.update(
        Event::Generate {
            records,
            payload_bytes,
        },
        &mut model,
    );

    let mut effect_order = Vec::new();
    let mut printed = Vec::new();

    while !cmd.is_done() {
        let Some(effect) = cmd.effects().next() else {
            panic!("command stalled waiting for an effect to resolve");
        };

        match effect {
            Effect::Store(mut request) => {
                effect_order.push("store");
                request
                    .resolve(StoreReport {
                        inserted_events: request.operation.records.len(),
                        ready_events: request.operation.records.len(),
                        blocked_events: 0,
                    })
                    .expect("store request should resolve");
            }
            Effect::Drain(mut request) => {
                effect_order.push("drain");
                request
                    .resolve(DrainReport {
                        applied_events: records,
                        unblocked_events: 0,
                    })
                    .expect("drain request should resolve");
            }
            Effect::Print(request) => {
                effect_order.push("print");
                printed.extend(request.operation.lines);
            }
        }
    }

    DemoRun {
        effect_order,
        printed,
        view: app.view(&model),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_emits_store_drain_print_in_order() {
        let app = PipelineFacade;
        let mut model = Model::default();

        let mut cmd = app.update(
            Event::Generate {
                records: 2,
                payload_bytes: 64,
            },
            &mut model,
        );

        let Effect::Store(mut store) = cmd.effects().next().expect("store effect") else {
            panic!("first effect should store records");
        };
        assert_eq!(store.operation.batch_id, 0);
        assert_eq!(store.operation.records.len(), 2);
        assert!(cmd.effects().next().is_none(), "drain waits for store");

        store
            .resolve(StoreReport {
                inserted_events: 2,
                ready_events: 2,
                blocked_events: 0,
            })
            .expect("store should resolve");

        let Effect::Drain(mut drain) = cmd.effects().next().expect("drain effect") else {
            panic!("second effect should drain ready events");
        };
        assert_eq!(
            drain.operation,
            DrainReady {
                batch_id: 0,
                batch_size: DEFAULT_READY_BATCH,
            }
        );
        assert!(cmd.effects().next().is_none(), "print waits for drain");

        drain
            .resolve(DrainReport {
                applied_events: 2,
                unblocked_events: 0,
            })
            .expect("drain should resolve");

        let Effect::Print(print) = cmd.effects().next().expect("print effect") else {
            panic!("third effect should print a summary");
        };
        assert_eq!(
            print.operation.lines,
            vec![
                "generated_events: 2",
                "ready_events: 2",
                "blocked_events: 0",
                "applied_events: 2",
                "unblocked_events: 0",
                "event_size_bytes: 64",
            ]
        );
        assert!(cmd.is_done());
    }

    #[test]
    fn demo_shell_runs_the_facade_sequence() {
        let run = run_demo_shell(3, 128);

        assert_eq!(run.effect_order, vec!["store", "drain", "print"]);
        assert_eq!(run.view.requested_records, 3);
        assert_eq!(
            run.printed,
            vec![
                "generated_events: 3",
                "ready_events: 3",
                "blocked_events: 0",
                "applied_events: 3",
                "unblocked_events: 0",
                "event_size_bytes: 128",
            ]
        );
    }
}
