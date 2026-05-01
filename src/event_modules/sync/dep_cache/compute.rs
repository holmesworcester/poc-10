//! Transitive-dependency closure helper for `dep_cache`.
//!
//! The closure `D(r)` is computed by BFS on the directed dep graph rooted
//! at `r`. Each event reports its immediate deps via the registry's
//! `ParsedEvent::dep_field_values()` accessor (plan.md uses this same
//! accessor as the one mechanism for declared deps).
//!
//! For decoupling from any specific event-store implementation, this helper
//! takes a closure `resolve_deps(event_id) -> Vec<dep_event_id>`. The
//! caller wires that to the canonical events table or to a test-double.
//!
//! `on_root_inserted` is the projector hook: BFS-compute `D(r)` and write
//! the rows to `dep_cache`. Idempotent under `INSERT OR IGNORE`.

use std::collections::{HashSet, VecDeque};

use rusqlite::{params, Connection};

use super::schema;
use super::state::DepRow;
use crate::runtime::control_loop::work_item::{BlakeId, WorkspaceId};

/// BFS the dep graph rooted at `root_event_id`. The closure
/// `resolve_deps(event_id)` returns immediate deps; `Err` is propagated.
///
/// `root_event_id` itself is NOT included in the result. The output is
/// deterministic given the input graph (BFS-discovery order).
pub fn compute_transitive<F, E>(
    root_event_id: &BlakeId,
    mut resolve_deps: F,
) -> Result<Vec<DepRow>, E>
where
    F: FnMut(&BlakeId) -> Result<Vec<BlakeId>, E>,
{
    let mut out: Vec<DepRow> = Vec::new();
    let mut seen: HashSet<BlakeId> = HashSet::new();
    seen.insert(*root_event_id);

    let mut frontier: VecDeque<(BlakeId, i32)> = VecDeque::new();
    frontier.push_back((*root_event_id, 0));

    while let Some((evt, depth)) = frontier.pop_front() {
        let deps = resolve_deps(&evt)?;
        for d in deps {
            if seen.insert(d) {
                out.push((d, depth + 1));
                frontier.push_back((d, depth + 1));
            }
        }
    }

    Ok(out)
}

/// Compute `D(r)` and persist it into `dep_cache`. The supplied
/// `resolve_deps` closure is exactly the dep-graph accessor — typically
/// "look up `event_id` in the canonical events table, parse, return
/// `dep_field_values()`".
pub fn on_root_inserted<F, E>(
    workspace_id: &WorkspaceId,
    root_event_id: &BlakeId,
    resolve_deps: F,
    db: &Connection,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(&BlakeId) -> Result<Vec<BlakeId>, E>,
    E: std::error::Error + 'static,
{
    schema::ensure_schema(db)?;

    let rows = compute_transitive(root_event_id, resolve_deps).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    for (dep_event_id, depth) in rows {
        db.execute(
            "INSERT OR IGNORE INTO dep_cache
                (workspace_id, root_event_id, dep_event_id, depth)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                workspace_id.to_vec(),
                root_event_id.to_vec(),
                dep_event_id.to_vec(),
                depth as i64,
            ],
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Test infallible resolver wrapper.
    #[derive(Debug)]
    struct Never;
    impl std::fmt::Display for Never {
        fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            Ok(())
        }
    }
    impl std::error::Error for Never {}

    fn graph(edges: &[(BlakeId, BlakeId)]) -> HashMap<BlakeId, Vec<BlakeId>> {
        let mut m: HashMap<BlakeId, Vec<BlakeId>> = HashMap::new();
        for (from, to) in edges {
            m.entry(*from).or_default().push(*to);
        }
        m
    }

    fn id(b: u8) -> BlakeId {
        [b; 32]
    }

    #[test]
    fn linear_chain_closure() {
        // r -> a -> b -> c
        let g = graph(&[(id(1), id(2)), (id(2), id(3)), (id(3), id(4))]);
        let result: Vec<DepRow> = compute_transitive(&id(1), |e| {
            Ok::<_, Never>(g.get(e).cloned().unwrap_or_default())
        })
        .unwrap();
        assert_eq!(result.len(), 3);
        // BFS order: a (depth 1), b (depth 2), c (depth 3).
        assert_eq!(result[0], (id(2), 1));
        assert_eq!(result[1], (id(3), 2));
        assert_eq!(result[2], (id(4), 3));
    }

    #[test]
    fn diamond_dedupes() {
        // r -> a, r -> b, a -> c, b -> c
        let g = graph(&[
            (id(1), id(2)),
            (id(1), id(3)),
            (id(2), id(4)),
            (id(3), id(4)),
        ]);
        let result = compute_transitive(&id(1), |e| {
            Ok::<_, Never>(g.get(e).cloned().unwrap_or_default())
        })
        .unwrap();
        // c appears once, with the shorter (BFS-discovered) depth = 2.
        assert_eq!(result.len(), 3);
        assert!(result.iter().any(|(d, _)| *d == id(4)));
        let c = result.iter().find(|(d, _)| *d == id(4)).unwrap();
        assert_eq!(c.1, 2);
    }
}
