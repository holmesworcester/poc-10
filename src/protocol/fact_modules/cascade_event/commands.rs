use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::store::Store;
use crate::protocol::runtime::ProtocolRuntime;

use super::fact::{CascadeEventFact, MAX_DEPS, PAYLOAD_BYTES};
use super::{layout, rows};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerateDepsReceipt {
    pub staged_events: usize,
    pub deps_per_event: usize,
    pub dep_edges: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayDepsReceipt {
    pub replayed_events: usize,
    pub applied_events: usize,
}

pub fn generate_deps(
    store: &Store,
    count: usize,
    deps_per_event: usize,
) -> Result<GenerateDepsReceipt, String> {
    if deps_per_event > MAX_DEPS {
        return Err(format!("DEPS_PER_EVENT must be at most {MAX_DEPS}"));
    }

    let mut ids = Vec::<FactId>::with_capacity(count);
    let mut staged_rows = Vec::with_capacity(count);
    let mut dep_edges = 0usize;

    for index in 0..count {
        let first_dependency = index.saturating_sub(deps_per_event);
        let dependencies = ids[first_dependency..index].to_vec();
        dep_edges += dependencies.len();
        let timestamp = u64::try_from(index + 1)
            .map_err(|_| "cascade event index exceeds timestamp range".to_string())?;
        let event = CascadeEventFact {
            timestamp,
            dependencies,
            payload: [(index % 251) as u8; PAYLOAD_BYTES],
        };
        let bytes = layout::encode_fact(&event)?;
        let fact = Fact::new(FactScope::Global, timestamp, bytes.clone());
        ids.push(fact.id);
        staged_rows.push(rows::staged_event_row(index as u64, bytes));
    }

    let existing_keys = store
        .table_rows(rows::CASCADE_STAGED_EVENT_ROWS)
        .map_err(|err| format!("load existing cascade staged rows: {err}"))?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    store
        .write_transaction(|tx| {
            tx.delete_table_rows_in_tx(rows::CASCADE_STAGED_EVENT_ROWS, existing_keys)?;
            tx.insert_table_rows_in_tx(staged_rows)
        })
        .map_err(|err| format!("write cascade staged rows: {err}"))?;

    Ok(GenerateDepsReceipt {
        staged_events: count,
        deps_per_event,
        dep_edges,
    })
}

pub fn replay_deps_reverse(runtime: &mut ProtocolRuntime) -> Result<ReplayDepsReceipt, String> {
    let mut rows = runtime
        .store()
        .table_rows(rows::CASCADE_STAGED_EVENT_ROWS)
        .map_err(|err| format!("load cascade staged rows: {err}"))?
        .into_iter()
        .map(|(key, value)| {
            let index = rows::decode_staged_event_key(&key)?;
            let event = layout::decode_fact(&value)?;
            Ok((index, event.timestamp, value))
        })
        .collect::<Result<Vec<_>, String>>()?;
    rows.sort_by_key(|(index, _, _)| *index);
    rows.reverse();

    for (_, timestamp, bytes) in &rows {
        runtime.submit_fact(Fact::new(FactScope::Global, *timestamp, bytes.clone()));
    }

    let limit = rows.len().max(1);
    for _ in 0..=rows.len() {
        let report = runtime.drain_projection(limit)?;
        if runtime.wake_loop().pending_len() == 0 || report.projections == 0 {
            break;
        }
    }
    runtime.save()?;

    Ok(ReplayDepsReceipt {
        replayed_events: rows.len(),
        applied_events: applied_cascade_event_count(runtime),
    })
}

fn applied_cascade_event_count(runtime: &ProtocolRuntime) -> usize {
    let role = crate::protocol::matchers::exact_event_role();
    runtime
        .facts()
        .filter(|fact| layout::decode_fact(&fact.bytes).is_ok())
        .filter(|fact| {
            runtime
                .wake_loop()
                .context(&fact.id)
                .is_some_and(|context| {
                    context.offers.iter().any(|offer| {
                        offer.owner == fact.id
                            && offer.role == role
                            && offer.scope == fact.scope
                            && offer.payload_ref == fact.id
                    })
                })
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_deps_reverse_applies_reverse_staged_dependencies() {
        let mut runtime = ProtocolRuntime::open_memory().expect("open runtime");
        generate_deps(runtime.store(), 2, 1).expect("generate staged deps");

        let receipt = replay_deps_reverse(&mut runtime).expect("replay reverse deps");

        assert_eq!(
            receipt,
            ReplayDepsReceipt {
                replayed_events: 2,
                applied_events: 2,
            }
        );
        assert_eq!(applied_cascade_event_count(&runtime), 2);
    }

    #[test]
    fn replay_deps_reverse_counts_only_events_that_offer_completion() {
        let mut runtime = ProtocolRuntime::open_memory().expect("open runtime");
        generate_deps(runtime.store(), 2, 1).expect("generate staged deps");
        runtime
            .store()
            .delete_table_rows(
                rows::CASCADE_STAGED_EVENT_ROWS,
                vec![rows::staged_event_key(0)],
            )
            .expect("delete dependency row");

        let receipt = replay_deps_reverse(&mut runtime).expect("replay partial deps");

        assert_eq!(
            receipt,
            ReplayDepsReceipt {
                replayed_events: 1,
                applied_events: 0,
            }
        );
        assert_eq!(applied_cascade_event_count(&runtime), 0);
    }
}
