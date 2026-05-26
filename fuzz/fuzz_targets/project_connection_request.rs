#![no_main]

use libfuzzer_sys::fuzz_target;
use topo::core::context::ContextOffer;
use topo::core::effects::PipelineEffects;
use topo::core::facts::{Fact, FactScope};
use topo::core::projectors::{MatchedContext, ProjectionContext, Projector, TimeRange};
use topo::protocol::connection::request::{layout, peer_retry_timeline};

fuzz_target!(|data: &[u8]| {
    let Ok(_request) = layout::decode_fact(data) else {
        return;
    };

    let fact = Fact::new(scope_choice(data), timestamp(data), data.to_vec());
    let projector = topo::protocol::connection::request::project::ConnectionRequestProjector::new();

    let empty_context = ProjectionContext::default();
    if let Ok(output) = projector.project(&fact, &empty_context) {
        if !output.needs.is_empty() {
            assert!(
                pipeline_effects_are_empty(&output.effects),
                "missing initial request context should not emit effects"
            );
        }

        let matched_context = ProjectionContext::from_matches(
            output
                .needs
                .into_iter()
                .enumerate()
                .map(|(index, need)| matched_arbitrary_payload(data, index, need))
                .collect(),
        );
        let _ = projector.project(&fact, &matched_context);
    }

    let timed_context = ProjectionContext::default().with_time_ranges(vec![TimeRange {
        timeline: peer_retry_timeline(),
        start_exclusive: None,
        end_inclusive: timestamp(data),
    }]);
    let _ = projector.project(&fact, &timed_context);
});

fn matched_arbitrary_payload(
    data: &[u8],
    index: usize,
    need: topo::core::context::ContextNeed,
) -> MatchedContext {
    let mut bytes = data
        .chunks(64)
        .nth(index)
        .unwrap_or(data)
        .to_vec();
    if bytes.is_empty() {
        bytes.push(index as u8);
    }
    let payload = Fact::new(need.scope.clone(), index as u64, bytes);
    let offer = ContextOffer {
        owner: payload.id,
        role: need.role.clone(),
        scope: need.scope.clone(),
        start_key: need.start_key.clone(),
        end_key: need.end_key.clone(),
    };
    MatchedContext {
        need,
        offer,
        payload,
    }
}

fn scope_choice(data: &[u8]) -> FactScope {
    if data.get(1).copied().unwrap_or_default() & 1 == 0 {
        FactScope::Local
    } else {
        FactScope::Global
    }
}

fn timestamp(data: &[u8]) -> u64 {
    let mut bytes = [0; 8];
    let len = data.len().min(bytes.len());
    bytes[..len].copy_from_slice(&data[..len]);
    u64::from_be_bytes(bytes)
}

fn pipeline_effects_are_empty(effects: &PipelineEffects) -> bool {
    effects.facts.is_empty()
        && effects.ephemeral_facts.is_empty()
        && effects.purged_facts.is_empty()
        && effects.row_mutations.is_empty()
        && effects.intents.is_empty()
        && effects.local_intents.is_empty()
}
