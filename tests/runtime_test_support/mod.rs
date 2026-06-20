use topo::core::runtime::{RecurringScheduler, Runtime, RuntimeTurnHost};
use topo::protocol::app::{CONTEXT_PROTOCOL, CONTEXT_RUNTIME};

pub fn initialize_context_runtime(runtime: &mut Runtime) {
    let mut scheduler = RecurringScheduler::install(CONTEXT_RUNTIME.handlers);
    runtime
        .run_turn(
            CONTEXT_PROTOCOL.runtime_turn,
            RuntimeTurnHost::local(),
            &mut scheduler,
            4096,
        )
        .expect("initialize runtime through local turn");
}

#[allow(dead_code)]
pub fn drain_projection_for_test(runtime: &mut Runtime, max_rounds: usize, limit: usize) -> bool {
    let mut progressed = false;
    for _ in 0..max_rounds {
        let status = runtime
            .drain_durable_projection(limit)
            .expect("drain durable projection batch");
        progressed |= status;
        let status = runtime
            .drain_incoming_projection(limit)
            .expect("drain incoming projection batch");
        progressed |= status;
        if runtime.pending_projection_count() == 0 {
            return progressed;
        }
    }
    panic!("projection work did not become idle within {max_rounds} rounds");
}

#[allow(dead_code)]
pub fn drain_runtime_work_for_test(runtime: &mut Runtime, max_rounds: usize, limit: usize) {
    for _ in 0..max_rounds {
        runtime
            .drain_durable_projection(limit)
            .expect("drain durable projection batch");
        runtime
            .drain_incoming_projection(limit)
            .expect("drain incoming projection batch");
        runtime
            .drain_durable_intents(limit)
            .expect("drain durable intent batch");
        runtime
            .drain_local_intents(limit)
            .expect("drain local intent batch");
        if runtime.pending_projection_count() == 0 && runtime.pending_intent_count() == 0 {
            return;
        }
    }
    panic!("runtime work did not become idle within {max_rounds} rounds");
}
