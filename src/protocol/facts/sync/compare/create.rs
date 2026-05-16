//! Sync compare response fact creation.

use crate::core::facts::{Fact, FactScope};
use crate::protocol::facts::sync;

use super::fact::{RangeSummary, SyncCompareFact, TimestampRange};

pub fn response_facts<'a>(
    compare_fact: &Fact,
    available_facts: impl IntoIterator<Item = &'a Fact>,
) -> Result<Vec<Fact>, String> {
    let compare = super::layout::decode_fact(&compare_fact.bytes)?;
    if !compare.response_requested {
        return Ok(Vec::new());
    }

    let range_facts = local_range_facts(available_facts, compare_fact.id, compare.range);
    let local_summary = summarize_range(&range_facts);
    let response = SyncCompareFact {
        connection_id: compare.connection_id,
        range: compare.range,
        summary: local_summary,
        response_requested: false,
    };
    let mut output = vec![Fact::new(
        compare_fact.scope.clone(),
        compare_fact.timestamp,
        super::layout::encode_fact(&response)?,
    )];

    if local_summary != compare.summary {
        for fact in range_facts {
            let have = sync::have_id::fact::SyncHaveIdFact {
                connection_id: compare.connection_id,
                timestamp: fact.timestamp,
                fact_id: fact.id,
            };
            output.push(Fact::new(
                compare_fact.scope.clone(),
                compare_fact.timestamp,
                sync::have_id::layout::encode_fact(&have)?,
            ));
        }
    }

    Ok(output)
}

fn local_range_facts<'a>(
    available_facts: impl IntoIterator<Item = &'a Fact>,
    compare_fact_id: [u8; 32],
    range: TimestampRange,
) -> Vec<&'a Fact> {
    let mut facts = available_facts
        .into_iter()
        .filter(|fact| fact.id != compare_fact_id)
        .filter(|fact| fact.scope != FactScope::Local)
        .filter(|fact| range.start <= fact.timestamp && fact.timestamp <= range.end)
        .filter(|fact| !is_sync_control_fact(fact))
        .collect::<Vec<_>>();
    facts.sort_by_key(|fact| (fact.timestamp, fact.id));
    facts
}

fn is_sync_control_fact(fact: &Fact) -> bool {
    matches!(
        fact.bytes.first().copied(),
        Some(super::layout::TYPE_SYNC_COMPARE)
            | Some(sync::have_id::layout::TYPE_SYNC_HAVE_ID)
            | Some(sync::need_id::layout::TYPE_SYNC_NEED_ID)
    )
}

fn summarize_range(facts: &[&Fact]) -> RangeSummary {
    let mut fingerprint = [0u8; 32];
    for fact in facts {
        let mut hash = blake3::Hasher::new();
        hash.update(b"topo:sync-range-summary:v1:");
        hash.update(&fact.timestamp.to_be_bytes());
        hash.update(&fact.id);
        let digest = hash.finalize();
        for (dst, src) in fingerprint.iter_mut().zip(digest.as_bytes()) {
            *dst ^= *src;
        }
    }
    RangeSummary {
        count: facts.len() as u64,
        fingerprint,
    }
}
