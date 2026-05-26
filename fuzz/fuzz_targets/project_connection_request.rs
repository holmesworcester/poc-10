#![no_main]

use libfuzzer_sys::fuzz_target;
use topo::core::context::ContextOffer;
use topo::core::crypto::ED25519_SIGNATURE_BYTES;
use topo::core::effects::PipelineEffects;
use topo::core::facts::{Fact, FactScope};
use topo::core::projectors::{MatchedContext, ProjectionContext, Projector, TimeRange};
use topo::protocol::connection::request::fact::ConnectionRequestFact;
use topo::protocol::connection::request::{layout, peer_retry_timeline};

fuzz_target!(|data: &[u8]| {
    exercise_request_bytes(data, data);
    let synthesized = synthesized_request_bytes(data);
    exercise_request_bytes(&synthesized, data);
});

fn exercise_request_bytes(bytes: &[u8], entropy: &[u8]) {
    let Ok(_request) = layout::decode_fact(bytes) else {
        return;
    };

    let fact = Fact::new(scope_choice(entropy), timestamp(entropy), bytes.to_vec());
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
                .map(|(index, need)| matched_arbitrary_payload(entropy, index, need))
                .collect(),
        );
        let _ = projector.project(&fact, &matched_context);
    }

    let timed_context = ProjectionContext::default().with_time_ranges(vec![TimeRange {
        timeline: peer_retry_timeline(),
        start_exclusive: None,
        end_inclusive: timestamp(entropy),
    }]);
    let _ = projector.project(&fact, &timed_context);
}

fn synthesized_request_bytes(data: &[u8]) -> Vec<u8> {
    let mut from_endpoint = array32(data, 0, 1);
    let mut to_endpoint = array32(data, 32, 2);
    if from_endpoint == to_endpoint {
        to_endpoint[0] = to_endpoint[0].wrapping_add(1).max(1);
    }
    if from_endpoint == [0; 32] {
        from_endpoint[0] = 1;
    }
    if to_endpoint == [0; 32] {
        to_endpoint[0] = 2;
    }

    let request = ConnectionRequestFact {
        from_endpoint,
        to_endpoint,
        nonce: array32(data, 64, 3),
        invite_fact_id: array32(data, 96, 4),
        bootstrap_hash: array32(data, 128, 5),
        invite_signature: signature(data, 160),
        invite_secret_fact_id: array32(data, 224, 6),
        initiator_ephemeral_secret_fact_id: array32(data, 256, 7),
        initiator_ephemeral_public_key: array32(data, 288, 8),
        from_listen_addr: listen_addr(data, 0),
        to_listen_addr: listen_addr(data, 1),
    };
    layout::encode_fact(&request).expect("synthetic request should encode")
}

fn array32(data: &[u8], offset: usize, salt: u8) -> [u8; 32] {
    let mut out = [salt; 32];
    fill_from(data, offset, &mut out);
    if out == [0; 32] {
        out[0] = salt.max(1);
    }
    out
}

fn signature(data: &[u8], offset: usize) -> [u8; ED25519_SIGNATURE_BYTES] {
    let mut out = [0; ED25519_SIGNATURE_BYTES];
    fill_from(data, offset, &mut out);
    out
}

fn fill_from(data: &[u8], offset: usize, out: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = data[(offset + index) % data.len()];
    }
}

fn listen_addr(data: &[u8], index: usize) -> Option<std::net::SocketAddr> {
    let selector = data.get(index).copied().unwrap_or_default();
    if selector & 1 == 0 {
        None
    } else {
        Some(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            40_000 + u16::from(selector),
        )))
    }
}

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
