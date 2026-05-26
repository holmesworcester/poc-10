#![no_main]

use libfuzzer_sys::fuzz_target;
use topo::core::context::{ContextNeed, ContextOffer};
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{Intent, IntentKind};
use topo::core::projectors::{ProjectionContext, ProjectionOutput, Projector, TimeWake, Timeline};
use topo::core::runtime::{Runtime, RuntimeDescription};

const FUZZ_RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: &[],
    row_mutation_tables: &[],
    projector: fuzz_projector,
    handlers: &[],
    command_excluded_handlers: &[],
};

fuzz_target!(|data: &[u8]| {
    let mut runtime = Runtime::open_memory(&FUZZ_RUNTIME).expect("open fuzz runtime");
    for (index, chunk) in data.chunks(24).take(4).enumerate() {
        let mut bytes = chunk.to_vec();
        if bytes.is_empty() {
            bytes.push(index as u8);
        }
        runtime.submit_fact(Fact::new(FactScope::Global, index as u64, bytes));
    }

    let _ = runtime.process_projection_until_idle(8, 32);
    runtime.process_due_time_range(fuzz_timeline(), None, timestamp(data), 32);
    let _ = runtime.process_projection_until_idle(8, 32);
});

fn fuzz_projector() -> Box<dyn Projector> {
    Box::new(FixedPointFuzzProjector)
}

#[derive(Debug, Clone, Copy)]
struct FixedPointFuzzProjector;

impl Projector for FixedPointFuzzProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let mode = fact.bytes.first().copied().unwrap_or_default() % 8;
        let key = key_from_fact(fact);
        let need = fuzz_need(fact.id, key);

        match mode {
            0 => Ok(ProjectionOutput::new().need(need)),
            1 => Ok(ProjectionOutput::new().offer(fuzz_offer(fact.id, key))),
            2 => Ok(ProjectionOutput::new().fact(Fact::new(
                FactScope::Global,
                fact.timestamp.saturating_add(1),
                vec![1, key[0]],
            ))),
            3 => {
                let mut output = ProjectionOutput::new();
                output.effects.ephemeral_facts.push(Fact::new(
                    FactScope::Local,
                    fact.timestamp,
                    vec![0, key[0]],
                ));
                Ok(output)
            }
            4 => {
                let mut output = ProjectionOutput::new();
                output.effects.ephemeral_facts.push(Fact::new(
                    FactScope::Local,
                    fact.timestamp,
                    vec![5, key[0]],
                ));
                Ok(output)
            }
            5 => Ok(ProjectionOutput::new()
                .need(need)
                .local_intent(fuzz_intent(key[0])?)),
            6 => Ok(ProjectionOutput::new().time_wake(TimeWake {
                owner: fact.id,
                timeline: fuzz_timeline(),
                at: u64::from(key[0]),
            })),
            _ => {
                if context.payload_for(&need).is_some() {
                    Ok(ProjectionOutput::new().local_intent(fuzz_intent(key[0])?))
                } else {
                    Ok(ProjectionOutput::new().need(need))
                }
            }
        }
    }
}

fn fuzz_need(owner: [u8; 32], key: [u8; 32]) -> ContextNeed {
    ContextNeed::range(owner, "fuzz_match", FactScope::Global, key, key)
}

fn fuzz_offer(owner: [u8; 32], key: [u8; 32]) -> ContextOffer {
    ContextOffer::range(owner, "fuzz_match", FactScope::Global, key, key)
}

fn fuzz_intent(key: u8) -> Result<Intent, String> {
    Ok(Intent::new(
        IntentKind::new("fuzz_followup")?,
        vec![key],
        vec![key],
    ))
}

fn fuzz_timeline() -> Timeline {
    Timeline::new("fuzz_time").expect("valid fuzz timeline")
}

fn key_from_fact(fact: &Fact) -> [u8; 32] {
    let mut key = [0; 32];
    let bytes = fact.bytes.get(1..).unwrap_or(&[]);
    let len = bytes.len().min(key.len());
    key[..len].copy_from_slice(&bytes[..len]);
    if len == 0 {
        key[0] = fact.bytes.first().copied().unwrap_or_default();
    }
    key
}

fn timestamp(data: &[u8]) -> u64 {
    let mut bytes = [0; 8];
    let len = data.len().min(bytes.len());
    bytes[..len].copy_from_slice(&data[..len]);
    u64::from_be_bytes(bytes)
}
