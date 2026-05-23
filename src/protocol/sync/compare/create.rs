//! Sync compare fact creation and response planning.
//!
//! Compare facts are the range-summary handshake that lets peers converge
//! without immediately sending every fact. This module summarizes local facts,
//! compares that summary with a peer's range, and either plans narrower child
//! compares or asks connection send handlers to send exact fact ids.
//!
//! Keep range-splitting and fingerprint logic here. Connection send handlers decide how to
//! frame facts, and `shared_fact` decides which facts a connection is allowed
//! to see; this module only plans what a sync response should contain.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::sync;

use super::fact::{RangeSummary, SyncCompareFact, TimestampRange};

const MAX_HAVE_IDS_PER_RANGE: usize = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompareResponsePlan {
    pub facts: Vec<Fact>,
    pub send_fact_ids: Vec<FactId>,
}

pub fn start_compare_fact<'a>(
    connection_id: FactId,
    available_facts: impl IntoIterator<Item = &'a Fact>,
) -> Result<Fact, String> {
    let range = TimestampRange::ROOT;
    let facts = local_range_facts(available_facts, [0; 32], range);
    let compare = SyncCompareFact {
        connection_id,
        range,
        summary: summarize_range(&facts),
        response_requested: true,
    };
    Ok(Fact::new(
        FactScope::Global,
        0,
        super::layout::encode_fact(&compare)?,
    ))
}

pub fn response_facts<'a>(
    compare_fact: &Fact,
    available_facts: impl IntoIterator<Item = &'a Fact>,
) -> Result<Vec<Fact>, String> {
    Ok(response_plan(compare_fact, available_facts)?.facts)
}

pub fn response_plan<'a>(
    compare_fact: &Fact,
    available_facts: impl IntoIterator<Item = &'a Fact>,
) -> Result<CompareResponsePlan, String> {
    let compare = super::layout::decode_fact(&compare_fact.bytes)?;
    let range_facts = local_range_facts(available_facts, compare_fact.id, compare.range);
    let local_summary = summarize_range(&range_facts);

    if local_summary == compare.summary {
        return Ok(CompareResponsePlan::default());
    }

    if local_summary.count == 0 {
        return if compare.response_requested {
            Ok(CompareResponsePlan {
                facts: vec![compare_response_fact(
                    compare_fact,
                    compare.connection_id,
                    compare.range,
                    local_summary,
                )?],
                send_fact_ids: Vec::new(),
            })
        } else {
            Ok(CompareResponsePlan::default())
        };
    }

    if range_facts.len() <= MAX_HAVE_IDS_PER_RANGE || one_timestamp(&range_facts) {
        let mut facts = Vec::new();
        if compare.response_requested && compare.summary.count > 0 {
            facts.push(compare_response_fact(
                compare_fact,
                compare.connection_id,
                compare.range,
                local_summary,
            )?);
        }
        return Ok(CompareResponsePlan {
            facts,
            send_fact_ids: range_facts.iter().map(|fact| fact.id).collect(),
        });
    }

    let (min_timestamp, max_timestamp) = timestamp_bounds(&range_facts)
        .ok_or_else(|| "non-empty range summary had no timestamp bounds".to_string())?;
    let mut facts = Vec::new();
    if compare.range.start < min_timestamp {
        facts.push(child_compare_fact(
            compare_fact,
            compare.connection_id,
            TimestampRange {
                start: compare.range.start,
                end: min_timestamp - 1,
            },
            RangeSummary::default(),
        )?);
    }
    if max_timestamp < compare.range.end {
        facts.push(child_compare_fact(
            compare_fact,
            compare.connection_id,
            TimestampRange {
                start: max_timestamp + 1,
                end: compare.range.end,
            },
            RangeSummary::default(),
        )?);
    }
    if let Some((left, right)) = (TimestampRange {
        start: min_timestamp,
        end: max_timestamp,
    })
    .split()
    {
        for range in [left, right] {
            let child_facts =
                local_range_facts(range_facts.iter().copied(), compare_fact.id, range);
            facts.push(child_compare_fact(
                compare_fact,
                compare.connection_id,
                range,
                summarize_range(&child_facts),
            )?);
        }
    }
    Ok(CompareResponsePlan {
        facts,
        send_fact_ids: Vec::new(),
    })
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

fn compare_response_fact(
    compare_fact: &Fact,
    connection_id: FactId,
    range: TimestampRange,
    summary: RangeSummary,
) -> Result<Fact, String> {
    Ok(Fact::new(
        compare_fact.scope.clone(),
        compare_fact.timestamp,
        super::layout::encode_fact(&SyncCompareFact {
            connection_id,
            range,
            summary,
            response_requested: false,
        })?,
    ))
}

fn child_compare_fact(
    compare_fact: &Fact,
    connection_id: FactId,
    range: TimestampRange,
    summary: RangeSummary,
) -> Result<Fact, String> {
    Ok(Fact::new(
        compare_fact.scope.clone(),
        compare_fact.timestamp,
        super::layout::encode_fact(&SyncCompareFact {
            connection_id,
            range,
            summary,
            response_requested: true,
        })?,
    ))
}

fn timestamp_bounds(facts: &[&Fact]) -> Option<(u64, u64)> {
    let min = facts.iter().map(|fact| fact.timestamp).min()?;
    let max = facts.iter().map(|fact| fact.timestamp).max()?;
    Some((min, max))
}

fn one_timestamp(facts: &[&Fact]) -> bool {
    timestamp_bounds(facts)
        .map(|(min, max)| min == max)
        .unwrap_or(true)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_compare_fact_summarizes_root_range() {
        let facts = [plain_fact(10, 1), plain_fact(20, 2)];

        let compare_fact = start_compare_fact([7; 32], facts.iter()).expect("start compare");
        let compare = super::super::layout::decode_fact(&compare_fact.bytes).expect("decode");

        assert_eq!(compare.connection_id, [7; 32]);
        assert_eq!(compare.range, TimestampRange::ROOT);
        assert_eq!(compare.summary.count, 2);
        assert!(compare.response_requested);
    }

    #[test]
    fn response_facts_split_large_mismatched_range() {
        let facts = (0..65)
            .map(|idx| plain_fact(10 + idx, idx as u8))
            .collect::<Vec<_>>();
        let compare_fact = compare_fact(
            TimestampRange {
                start: 10,
                end: 100,
            },
            RangeSummary::default(),
            true,
        );

        let output = response_facts(&compare_fact, facts.iter()).expect("response facts");

        assert!(output.len() >= 2);
        assert!(output
            .iter()
            .all(|fact| fact.bytes.first() == Some(&super::super::layout::TYPE_SYNC_COMPARE)));
        assert!(output.iter().all(|fact| {
            super::super::layout::decode_fact(&fact.bytes)
                .expect("decode compare")
                .response_requested
        }));
    }

    #[test]
    fn response_plan_batches_local_facts_for_small_mismatched_range() {
        let facts = [plain_fact(10, 1), plain_fact(20, 2)];
        let compare_fact = compare_fact(TimestampRange::ROOT, RangeSummary::default(), true);

        let output = response_plan(&compare_fact, facts.iter()).expect("response plan");

        assert!(output.facts.is_empty());
        assert_eq!(
            output.send_fact_ids,
            facts.iter().map(|fact| fact.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn empty_local_range_answers_requested_compare() {
        let compare_fact = compare_fact(
            TimestampRange::ROOT,
            RangeSummary {
                count: 1,
                fingerprint: [3; 32],
            },
            true,
        );

        let output = response_facts(&compare_fact, std::iter::empty()).expect("response facts");

        assert_eq!(output.len(), 1);
        let compare = super::super::layout::decode_fact(&output[0].bytes).expect("decode compare");
        assert_eq!(compare.summary, RangeSummary::default());
        assert!(!compare.response_requested);
    }

    fn plain_fact(timestamp: u64, byte: u8) -> Fact {
        Fact::new(FactScope::Global, timestamp, vec![byte])
    }

    fn compare_fact(
        range: TimestampRange,
        summary: RangeSummary,
        response_requested: bool,
    ) -> Fact {
        Fact::new(
            FactScope::Global,
            0,
            super::super::layout::encode_fact(&SyncCompareFact {
                connection_id: [7; 32],
                range,
                summary,
                response_requested,
            })
            .expect("encode compare"),
        )
    }
}
