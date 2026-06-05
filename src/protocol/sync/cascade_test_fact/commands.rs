//! Commands for constructing and replaying synthetic dependency graphs.
//!
//! The cascade harness lets sync and projection tests create facts whose
//! dependencies are known in advance. `generate_deps` stores encoded facts in a
//! staging table without submitting them. `replay_deps_reverse` submits that
//! graph in reverse order, then materializes the context offers that would
//! appear only after each dependency becomes complete.
//!
//! Keep the test-harness mechanics here rather than in core pipeline code.
//! These commands deliberately model one narrow behavior: facts do not count as
//! applied until every declared dependency has already offered completion.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::runtime::Runtime;
use crate::core::store::Store;
use std::collections::BTreeSet;

use super::fact::{CascadeDependencies, CascadeTestFact, MAX_DEPS, PAYLOAD_BYTES};
use super::{decode, encode, staging};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerateDepsReceipt {
    pub staged_facts: usize,
    pub deps_per_fact: usize,
    pub dep_edges: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayDepsReceipt {
    pub replayed_facts: usize,
    pub applied_facts: usize,
}

pub fn generate_deps(
    store: &Store,
    count: usize,
    deps_per_fact: usize,
) -> Result<GenerateDepsReceipt, String> {
    if deps_per_fact > MAX_DEPS {
        return Err(format!("DEPS_PER_FACT must be at most {MAX_DEPS}"));
    }

    let mut ids = Vec::<FactId>::with_capacity(count);
    let mut staged_rows = Vec::with_capacity(count);
    let mut dep_edges = 0usize;

    for index in 0..count {
        let first_dependency = index.saturating_sub(deps_per_fact);
        let dependencies = CascadeDependencies::new(&ids[first_dependency..index])?;
        dep_edges += dependencies.len();
        let timestamp = u64::try_from(index + 1)
            .map_err(|_| "cascade fact index exceeds timestamp range".to_string())?;
        let fact = CascadeTestFact {
            timestamp,
            dependencies,
            payload: [(index % 251) as u8; PAYLOAD_BYTES],
        };
        let bytes = encode::encode_fact(&fact)?;
        let fact = Fact::new(FactScope::Global, timestamp, bytes.clone());
        ids.push(fact.id);
        staged_rows.push(staging::staged_fact_row(index as u64, bytes));
    }

    let existing_keys = store
        .table_rows(staging::CASCADE_STAGED_FACT_ROWS)
        .map_err(|err| format!("load existing cascade staged rows: {err}"))?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    store
        .write_transaction(|tx| {
            tx.delete_table_rows_in_tx(staging::CASCADE_STAGED_FACT_ROWS, existing_keys)?;
            tx.insert_table_rows_in_tx(staged_rows)
        })
        .map_err(|err| format!("write cascade staged rows: {err}"))?;

    Ok(GenerateDepsReceipt {
        staged_facts: count,
        deps_per_fact,
        dep_edges,
    })
}

pub fn replay_deps_reverse(runtime: &mut Runtime) -> Result<ReplayDepsReceipt, String> {
    let mut rows = runtime
        .store()
        .table_rows(staging::CASCADE_STAGED_FACT_ROWS)
        .map_err(|err| format!("load cascade staged rows: {err}"))?
        .into_iter()
        .map(|(key, value)| {
            let index = staging::decode_staged_fact_key(&key)?;
            let fact = decode::decode_fact(&value)?;
            Ok((index, fact.timestamp, value))
        })
        .collect::<Result<Vec<_>, String>>()?;
    rows.sort_by_key(|(index, _, _)| *index);
    rows.reverse();

    runtime
        .submit_facts(rows.iter().map(|(_, timestamp, bytes)| {
            Fact::new(FactScope::Global, *timestamp, bytes.clone())
        }))?;
    materialize_replayed_cascade_offers(runtime, &rows)?;

    Ok(ReplayDepsReceipt {
        replayed_facts: rows.len(),
        applied_facts: applied_cascade_test_fact_count(runtime),
    })
}

fn materialize_replayed_cascade_offers(
    runtime: &Runtime,
    rows: &[(u64, u64, Vec<u8>)],
) -> Result<usize, String> {
    let mut ordered = rows.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(index, timestamp, _)| (*timestamp, *index));

    let mut applied = BTreeSet::<FactId>::new();
    let mut offers = Vec::new();
    let mut completed_fact_ids = Vec::new();

    for (_, timestamp, bytes) in ordered {
        let decoded = decode::decode_fact(bytes)?;
        if decoded.timestamp != *timestamp {
            return Err("cascade staged timestamp mismatch".to_string());
        }
        let fact = Fact::new(FactScope::Global, *timestamp, bytes.clone());
        if !decoded
            .dependencies
            .iter()
            .all(|dependency| applied.contains(&dependency))
        {
            continue;
        }

        let offer = crate::core::context::ContextOffer::range(
            fact.id,
            "sync_exact_fact",
            fact.scope.clone(),
            fact.id,
            fact.id,
        );
        offers.push(offer);
        completed_fact_ids.push(fact.id);
        applied.insert(fact.id);
    }

    runtime.commit_projected_context_offers(&offers, &completed_fact_ids)?;

    Ok(applied.len())
}

fn applied_cascade_test_fact_count(runtime: &Runtime) -> usize {
    let role = "sync_exact_fact";
    runtime
        .facts()
        .filter(|fact| decode::decode_fact(fact.body()).is_ok())
        .filter(|fact| {
            crate::core::pipeline::context_store::persisted_context(runtime.store(), &fact.id)
                .ok()
                .flatten()
                .is_some_and(|context| {
                    context.offers.iter().any(|offer| {
                        offer.owner == fact.id
                            && offer.role.as_str() == role
                            && offer.scope == fact.scope
                    })
                })
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::app::MATCH_RUNTIME;

    #[test]
    fn replay_deps_reverse_applies_reverse_staged_dependencies() {
        let mut runtime = Runtime::open_memory(&MATCH_RUNTIME).expect("open runtime");
        generate_deps(runtime.store(), 2, 1).expect("generate staged deps");

        let receipt = replay_deps_reverse(&mut runtime).expect("replay reverse deps");

        assert_eq!(
            receipt,
            ReplayDepsReceipt {
                replayed_facts: 2,
                applied_facts: 2,
            }
        );
        assert_eq!(applied_cascade_test_fact_count(&runtime), 2);
    }

    #[test]
    fn replay_deps_reverse_counts_only_facts_that_offer_completion() {
        let mut runtime = Runtime::open_memory(&MATCH_RUNTIME).expect("open runtime");
        generate_deps(runtime.store(), 2, 1).expect("generate staged deps");
        runtime
            .store()
            .delete_table_rows(
                staging::CASCADE_STAGED_FACT_ROWS,
                vec![staging::staged_fact_key(0)],
            )
            .expect("delete dependency row");

        let receipt = replay_deps_reverse(&mut runtime).expect("replay partial deps");

        assert_eq!(
            receipt,
            ReplayDepsReceipt {
                replayed_facts: 1,
                applied_facts: 0,
            }
        );
        assert_eq!(applied_cascade_test_fact_count(&runtime), 0);
    }
}
