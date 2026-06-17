//! Durable sync contribution rows and connection queries.
//!
//! Fact projectors record which workspace a fact may be sent through and which
//! validated context belongs to that fact's sync leaf. This module turns those
//! rows into connection-specific fact lists by checking endpoint membership,
//! connection workspace authorization, and whether the named fact still exists
//! in the core db.
//!
//! Keep sync visibility here. Fact admission belongs to projectors, and
//! connection framing belongs to `send_facts_on_connection`; callers use this
//! file to ask what a peer is allowed to learn.

use crate::core::db::{Db, TableInsert, TableName, TypedTableSchema, Value, DEFAULT_QUERY_LIMIT};
use crate::core::fact_db::persisted_fact;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::{
    auth, connection,
    sync::{
        compare::fact::{RangeSummary, TimestampRange},
        share_fact_with_sync,
    },
};
use rusqlite::{params, OptionalExtension, Row};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const SHAREABLE_FACT_ROWS: TableName = TableName::new("sync_shareable_fact_rows");
pub const NEGENTROPY_LEAF_ROWS: TableName = TableName::new("sync_negentropy_leaf_rows");
pub const NEGENTROPY_CONTEXT_HAVE_ROWS: TableName =
    TableName::new("sync_negentropy_context_have_rows");
pub const NEGENTROPY_NODE_ROWS: TableName = TableName::new("sync_negentropy_node_rows");

pub const SHAREABLE_FACT_TABLE: TypedTableSchema = TypedTableSchema {
    table: SHAREABLE_FACT_ROWS,
    columns: &["workspace_id", "fact_id", "timestamp_ms"],
    key_columns: &["workspace_id", "fact_id"],
};
pub const NEGENTROPY_LEAF_TABLE: TypedTableSchema = TypedTableSchema {
    table: NEGENTROPY_LEAF_ROWS,
    columns: &[
        "workspace_id",
        "owner_fact_id",
        "timestamp_ms",
        "contribution_fingerprint",
    ],
    key_columns: &["workspace_id", "owner_fact_id"],
};
pub const NEGENTROPY_CONTEXT_HAVE_TABLE: TypedTableSchema = TypedTableSchema {
    table: NEGENTROPY_CONTEXT_HAVE_ROWS,
    columns: &["workspace_id", "owner_fact_id", "context_fact_id"],
    key_columns: &["workspace_id", "owner_fact_id", "context_fact_id"],
};
pub const NEGENTROPY_NODE_TABLE: TypedTableSchema = TypedTableSchema {
    table: NEGENTROPY_NODE_ROWS,
    columns: &[
        "workspace_id",
        "level",
        "start_timestamp_ms",
        "count",
        "fingerprint",
    ],
    key_columns: &["workspace_id", "level", "start_timestamp_ms"],
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareableFactRow {
    pub workspace_id: FactId,
    pub fact_id: FactId,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegentropyLeafRow {
    pub workspace_id: FactId,
    pub owner_fact_id: FactId,
    pub timestamp_ms: u64,
    pub contribution_fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegentropyContextHaveRow {
    pub workspace_id: FactId,
    pub owner_fact_id: FactId,
    pub context_fact_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegentropyNodeRow {
    pub workspace_id: FactId,
    pub level: u8,
    pub start_timestamp_ms: u64,
    pub summary: RangeSummary,
}

pub fn shareable_fact_row(row: ShareableFactRow) -> TableInsert {
    SHAREABLE_FACT_TABLE.insert(vec![
        Value::Bytes(row.workspace_id.to_vec()),
        Value::Bytes(row.fact_id.to_vec()),
        Value::U64(row.timestamp_ms),
    ])
}

pub fn decode_shareable_fact_row(row: &Row<'_>) -> rusqlite::Result<ShareableFactRow> {
    Ok(ShareableFactRow {
        workspace_id: row.get(0)?,
        fact_id: row.get(1)?,
        timestamp_ms: row.get::<_, i64>(2)? as u64,
    })
}

fn negentropy_leaf_row(row: NegentropyLeafRow) -> TableInsert {
    NEGENTROPY_LEAF_TABLE.insert(vec![
        Value::Bytes(row.workspace_id.to_vec()),
        Value::Bytes(row.owner_fact_id.to_vec()),
        Value::U64(row.timestamp_ms),
        Value::Bytes(row.contribution_fingerprint.to_vec()),
    ])
}

fn decode_negentropy_leaf_row(row: &Row<'_>) -> rusqlite::Result<NegentropyLeafRow> {
    Ok(NegentropyLeafRow {
        workspace_id: row.get(0)?,
        owner_fact_id: row.get(1)?,
        timestamp_ms: row.get::<_, i64>(2)? as u64,
        contribution_fingerprint: row.get(3)?,
    })
}

fn negentropy_context_have_row(row: NegentropyContextHaveRow) -> TableInsert {
    NEGENTROPY_CONTEXT_HAVE_TABLE.insert(vec![
        Value::Bytes(row.workspace_id.to_vec()),
        Value::Bytes(row.owner_fact_id.to_vec()),
        Value::Bytes(row.context_fact_id.to_vec()),
    ])
}

fn decode_negentropy_context_have_row(row: &Row<'_>) -> rusqlite::Result<NegentropyContextHaveRow> {
    Ok(NegentropyContextHaveRow {
        workspace_id: row.get(0)?,
        owner_fact_id: row.get(1)?,
        context_fact_id: row.get(2)?,
    })
}

fn negentropy_node_row(row: NegentropyNodeRow) -> TableInsert {
    NEGENTROPY_NODE_TABLE.insert(vec![
        Value::Bytes(row.workspace_id.to_vec()),
        Value::U64(u64::from(row.level)),
        Value::U64(row.start_timestamp_ms),
        Value::U64(row.summary.count),
        Value::Bytes(row.summary.fingerprint.to_vec()),
    ])
}

fn decode_negentropy_node_row(row: &Row<'_>) -> rusqlite::Result<NegentropyNodeRow> {
    Ok(NegentropyNodeRow {
        workspace_id: row.get(0)?,
        level: row.get::<_, i64>(1)? as u8,
        start_timestamp_ms: row.get::<_, i64>(2)? as u64,
        summary: RangeSummary {
            count: row.get::<_, i64>(3)? as u64,
            fingerprint: row.get(4)?,
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    pub indexed_facts: usize,
    pub root_count: u64,
    pub root_fingerprint: [u8; 32],
    pub pending_purges: usize,
}

pub fn record_sync_contribution(
    store: &Db,
    input: &share_fact_with_sync::ShareFactWithSync,
    owner: Option<&Fact>,
) -> Result<bool, String> {
    match input.state {
        share_fact_with_sync::SyncShareState::Upsert => {
            let owner = owner
                .ok_or_else(|| "share_fact_with_sync upsert requires owner fact".to_string())?;
            validate_sync_owner(
                input.workspace_id,
                input.owner_fact_id,
                input.timestamp_ms,
                owner,
            )?;
            upsert_sync_contribution(store, input, owner)
        }
        share_fact_with_sync::SyncShareState::Retract => retract_sync_contribution(store, input),
    }
}

fn validate_sync_owner(
    workspace_id: FactId,
    owner_fact_id: FactId,
    timestamp_ms: u64,
    owner: &Fact,
) -> Result<(), String> {
    if owner.id != owner_fact_id {
        return Err("share_fact_with_sync owner fact id mismatch".to_string());
    }
    if owner.timestamp != timestamp_ms {
        return Err("share_fact_with_sync timestamp does not match owner fact".to_string());
    }
    match &owner.scope {
        FactScope::Scoped { kind, id } if kind.as_str() == "workspace" => {
            if id != &workspace_id {
                return Err("share_fact_with_sync owner scope does not match workspace".to_string());
            }
        }
        FactScope::Global => {}
        _ => {
            return Err(
                "share_fact_with_sync requires a workspace-scoped or global owner fact".to_string(),
            );
        }
    }
    Ok(())
}

fn upsert_sync_contribution(
    store: &Db,
    input: &share_fact_with_sync::ShareFactWithSync,
    owner: &Fact,
) -> Result<bool, String> {
    store
        .write_transaction(|tx| {
            let old_leaf =
                negentropy_leaf_row_for_owner(tx, input.workspace_id, input.owner_fact_id)
                    .map_err(rusqlite::Error::InvalidParameterName)?;
            if let Some(old_leaf) = &old_leaf {
                if old_leaf.timestamp_ms != input.timestamp_ms {
                    return Err(rusqlite::Error::InvalidParameterName(
                        "share_fact_with_sync timestamp changed for existing owner".to_string(),
                    ));
                }
            }

            let mut context_have =
                negentropy_context_have_for_leaf(tx, input.workspace_id, input.owner_fact_id)
                    .map_err(rusqlite::Error::InvalidParameterName)?;
            context_have.extend(input.context_have.iter().copied());
            context_have.sort();
            context_have.dedup();
            let new_fingerprint = contribution_fingerprint(
                input.workspace_id,
                input.owner_fact_id,
                input.timestamp_ms,
                &context_have,
            );
            if old_leaf
                .as_ref()
                .map(|leaf| leaf.contribution_fingerprint == new_fingerprint)
                .unwrap_or(false)
            {
                return Ok(false);
            }

            let old_summary = old_leaf.as_ref().map(|leaf| RangeSummary {
                count: 1,
                fingerprint: leaf.contribution_fingerprint,
            });
            let new_summary = RangeSummary {
                count: 1,
                fingerprint: new_fingerprint,
            };
            let leaf_row = negentropy_leaf_row(NegentropyLeafRow {
                workspace_id: input.workspace_id,
                owner_fact_id: input.owner_fact_id,
                timestamp_ms: input.timestamp_ms,
                contribution_fingerprint: new_fingerprint,
            });
            let shareable_row = shareable_fact_row(ShareableFactRow {
                workspace_id: input.workspace_id,
                fact_id: owner.id,
                timestamp_ms: owner.timestamp,
            });
            let context_rows = context_have
                .iter()
                .map(|context_fact_id| {
                    negentropy_context_have_row(NegentropyContextHaveRow {
                        workspace_id: input.workspace_id,
                        owner_fact_id: input.owner_fact_id,
                        context_fact_id: *context_fact_id,
                    })
                })
                .collect::<Vec<_>>();
            tx.delete_where_in_tx(&NEGENTROPY_LEAF_TABLE.delete_by_key(vec![
                Value::Bytes(input.workspace_id.to_vec()),
                Value::Bytes(input.owner_fact_id.to_vec()),
            ]))?;
            delete_context_rows_for_leaf(tx, input.workspace_id, input.owner_fact_id)?;
            crate::core::perf_profile::measure_result("negentropy_update_path", || {
                update_node_path_in_tx(
                    tx,
                    input.workspace_id,
                    input.timestamp_ms,
                    old_summary,
                    Some(new_summary),
                )
            })?;
            tx.insert_values_in_tx(&shareable_row)?;
            tx.insert_values_in_tx(&leaf_row)?;
            for row in context_rows {
                tx.insert_values_in_tx(&row)?;
            }
            Ok(true)
        })
        .map_err(|err| format!("record sync contribution rows: {err}"))
}

fn retract_sync_contribution(
    store: &Db,
    input: &share_fact_with_sync::ShareFactWithSync,
) -> Result<bool, String> {
    store
        .write_transaction(|tx| {
            let Some(old_leaf) =
                negentropy_leaf_row_for_owner(tx, input.workspace_id, input.owner_fact_id)
                    .map_err(rusqlite::Error::InvalidParameterName)?
            else {
                return Ok(false);
            };
            let old_summary = RangeSummary {
                count: 1,
                fingerprint: old_leaf.contribution_fingerprint,
            };
            tx.delete_where_in_tx(&SHAREABLE_FACT_TABLE.delete_by_key(vec![
                Value::Bytes(input.workspace_id.to_vec()),
                Value::Bytes(input.owner_fact_id.to_vec()),
            ]))?;
            tx.delete_where_in_tx(&NEGENTROPY_LEAF_TABLE.delete_by_key(vec![
                Value::Bytes(input.workspace_id.to_vec()),
                Value::Bytes(input.owner_fact_id.to_vec()),
            ]))?;
            delete_context_rows_for_leaf(tx, input.workspace_id, input.owner_fact_id)?;
            crate::core::perf_profile::measure_result("negentropy_update_path", || {
                update_node_path_in_tx(
                    tx,
                    input.workspace_id,
                    old_leaf.timestamp_ms,
                    Some(old_summary),
                    None,
                )
            })?;
            Ok(true)
        })
        .map_err(|err| format!("retract sync contribution rows: {err}"))
}

fn update_node_path_in_tx(
    store: &Db,
    workspace_id: FactId,
    timestamp_ms: u64,
    old_summary: Option<RangeSummary>,
    new_summary: Option<RangeSummary>,
) -> rusqlite::Result<()> {
    for (level, start_timestamp_ms) in node_path(timestamp_ms) {
        let current = negentropy_node_row_for_node(store, workspace_id, level, start_timestamp_ms)
            .map_err(rusqlite::Error::InvalidParameterName)?;
        let mut summary = current
            .map(|row| row.summary)
            .unwrap_or_else(RangeSummary::default);
        if let Some(old) = old_summary {
            summary.count = summary.count.saturating_sub(old.count);
            xor_fingerprint(&mut summary.fingerprint, old.fingerprint);
        }
        if let Some(new) = new_summary {
            summary.count = summary.count.saturating_add(new.count);
            xor_fingerprint(&mut summary.fingerprint, new.fingerprint);
        }
        store.delete_where_in_tx(&NEGENTROPY_NODE_TABLE.delete_by_key(vec![
            Value::Bytes(workspace_id.to_vec()),
            Value::U64(u64::from(level)),
            Value::U64(start_timestamp_ms),
        ]))?;
        if summary.count != 0 || summary.fingerprint != [0; 32] {
            store.insert_values_in_tx(&negentropy_node_row(NegentropyNodeRow {
                workspace_id,
                level,
                start_timestamp_ms,
                summary,
            }))?;
        }
    }
    Ok(())
}

fn delete_context_rows_for_leaf(
    store: &Db,
    workspace_id: FactId,
    owner_fact_id: FactId,
) -> rusqlite::Result<usize> {
    store.delete_where_in_tx(&crate::core::db::TableDeleteWhere {
        table: NEGENTROPY_CONTEXT_HAVE_ROWS,
        columns: &["workspace_id", "owner_fact_id"],
        values: vec![
            Value::Bytes(workspace_id.to_vec()),
            Value::Bytes(owner_fact_id.to_vec()),
        ],
    })
}

fn negentropy_node_row_for_node(
    store: &Db,
    workspace_id: FactId,
    level: u8,
    start_timestamp_ms: u64,
) -> Result<Option<NegentropyNodeRow>, String> {
    store
        .conn()
        .query_row(
            "SELECT workspace_id, level, start_timestamp_ms, count, fingerprint
             FROM sync_negentropy_node_rows
             WHERE workspace_id = ?1 AND level = ?2 AND start_timestamp_ms = ?3
             LIMIT 1",
            params![workspace_id, i64::from(level), start_timestamp_ms as i64,],
            decode_negentropy_node_row,
        )
        .optional()
        .map_err(|err| format!("load negentropy node row: {err}"))
}

fn node_path(timestamp_ms: u64) -> impl Iterator<Item = (u8, u64)> {
    (0u8..=64).map(move |level| {
        let start = if level == 64 {
            0
        } else {
            let width = 1u64 << level;
            timestamp_ms & !(width - 1)
        };
        (level, start)
    })
}

fn covering_nodes(start: u64, end: u64) -> Vec<(u8, u64)> {
    let mut out = Vec::new();
    cover_node(64, 0, start, end, &mut out);
    out
}

fn cover_node(
    level: u8,
    node_start: u64,
    query_start: u64,
    query_end: u64,
    out: &mut Vec<(u8, u64)>,
) {
    let node_end = node_end(level, node_start);
    if query_end < node_start || node_end < query_start {
        return;
    }
    if query_start <= node_start && node_end <= query_end {
        out.push((level, node_start));
        return;
    }
    if level == 0 {
        return;
    }
    let child_level = level - 1;
    let right_start = if child_level == 63 {
        1u64 << 63
    } else {
        node_start + (1u64 << child_level)
    };
    cover_node(child_level, node_start, query_start, query_end, out);
    cover_node(child_level, right_start, query_start, query_end, out);
}

fn node_end(level: u8, start: u64) -> u64 {
    if level == 64 {
        u64::MAX
    } else {
        start + ((1u64 << level) - 1)
    }
}

fn contribution_fingerprint(
    workspace_id: FactId,
    owner_fact_id: FactId,
    timestamp_ms: u64,
    context_have: &[FactId],
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync-contribution:v1:");
    hash.update(&workspace_id);
    hash.update(&owner_fact_id);
    hash.update(&timestamp_ms.to_be_bytes());
    hash.update(&(context_have.len() as u64).to_be_bytes());
    for fact_id in context_have {
        hash.update(fact_id);
    }
    *hash.finalize().as_bytes()
}

fn xor_fingerprint(dst: &mut [u8; 32], src: [u8; 32]) {
    for (dst, src) in dst.iter_mut().zip(src) {
        *dst ^= src;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto;
    use crate::core::facts::ScopeKind;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::protocol::auth::endpoint::{self as endpoint_rows, fact::EndpointFact};
    use crate::protocol::auth::endpoint_shared::{
        self as endpoint_shared_rows,
        fact::{EndpointDeviceName, EndpointRole, EndpointSharedFact},
    };
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn store() -> Db {
        Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store")
    }

    fn fact(workspace_id: FactId, timestamp_ms: u64, seed: u8) -> Fact {
        Fact::new(
            FactScope::Scoped {
                kind: ScopeKind::new("workspace").unwrap(),
                id: workspace_id,
            },
            timestamp_ms,
            vec![seed],
        )
    }

    fn upsert(
        workspace_id: FactId,
        fact: &Fact,
        context_have: Vec<FactId>,
    ) -> share_fact_with_sync::ShareFactWithSync {
        share_fact_with_sync::ShareFactWithSync {
            workspace_id,
            owner_fact_id: fact.id,
            timestamp_ms: fact.timestamp,
            state: share_fact_with_sync::SyncShareState::Upsert,
            context_have,
        }
    }

    #[test]
    fn sync_contribution_upsert_updates_leaf_path_and_range_summary() {
        let store = store();
        let workspace_id = [9; 32];
        let fact = fact(workspace_id, 42, 1);

        assert!(record_sync_contribution(
            &store,
            &upsert(workspace_id, &fact, Vec::new()),
            Some(&fact)
        )
        .expect("upsert contribution"));

        assert_eq!(
            shareable_fact_rows(&store).expect("shareable rows").len(),
            1
        );
        assert_eq!(negentropy_leaf_rows(&store).expect("leaf rows").len(), 1);
        assert_eq!(negentropy_node_rows(&store).expect("node rows").len(), 65);
        let root = range_summary_for_workspace(&store, workspace_id, TimestampRange::ROOT)
            .expect("root summary");
        assert_eq!(root.count, 1);
        assert_ne!(root.fingerprint, [0; 32]);
        let exact = range_summary_for_workspace(
            &store,
            workspace_id,
            TimestampRange { start: 42, end: 42 },
        )
        .expect("exact summary");
        assert_eq!(exact, root);
        let empty = range_summary_for_workspace(
            &store,
            workspace_id,
            TimestampRange { start: 43, end: 43 },
        )
        .expect("empty summary");
        assert_eq!(empty, RangeSummary::default());
    }

    #[test]
    fn sync_contribution_is_idempotent_and_monotonically_adds_context() {
        let store = store();
        let workspace_id = [9; 32];
        let fact = fact(workspace_id, 42, 1);
        let empty = upsert(workspace_id, &fact, Vec::new());

        assert!(record_sync_contribution(&store, &empty, Some(&fact)).expect("first upsert"));
        let first_root = range_summary_for_workspace(&store, workspace_id, TimestampRange::ROOT)
            .expect("first root");
        assert!(!record_sync_contribution(&store, &empty, Some(&fact)).expect("repeat upsert"));
        assert_eq!(
            range_summary_for_workspace(&store, workspace_id, TimestampRange::ROOT)
                .expect("repeat root"),
            first_root
        );

        let richer = upsert(workspace_id, &fact, vec![[7; 32]]);
        assert!(record_sync_contribution(&store, &richer, Some(&fact)).expect("richer upsert"));
        let richer_root = range_summary_for_workspace(&store, workspace_id, TimestampRange::ROOT)
            .expect("richer root");
        assert_eq!(richer_root.count, 1);
        assert_ne!(richer_root.fingerprint, first_root.fingerprint);

        assert!(!record_sync_contribution(&store, &empty, Some(&fact)).expect("older upsert"));
        assert_eq!(
            negentropy_context_have_for_leaf(&store, workspace_id, fact.id).expect("context rows"),
            vec![[7; 32]]
        );
        assert_eq!(
            range_summary_for_workspace(&store, workspace_id, TimestampRange::ROOT)
                .expect("final root"),
            richer_root
        );
    }

    #[test]
    fn concurrent_duplicate_upserts_do_not_double_count_tree_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("sync.db");
        let workspace_id = [9; 32];
        let fact = fact(workspace_id, 42, 1);
        let input = upsert(workspace_id, &fact, Vec::new());
        let barrier = Arc::new(Barrier::new(2));
        drop(
            Db::open_disk_with_schema_sources(&path, &[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("seed store schema"),
        );

        let handles = (0..2)
            .map(|_| {
                let path = path.clone();
                let fact = fact.clone();
                let input = input.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let store = Db::open_disk_with_schema_sources(
                        &path,
                        &[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE],
                    )
                    .expect("open db");
                    barrier.wait();
                    record_sync_contribution(&store, &input, Some(&fact))
                        .expect("record contribution")
                })
            })
            .collect::<Vec<_>>();

        let changed = handles
            .into_iter()
            .map(|handle| handle.join().expect("join"))
            .filter(|changed| *changed)
            .count();
        assert_eq!(changed, 1);

        let store =
            Db::open_disk_with_schema_sources(&path, &[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("reopen db");
        assert_eq!(negentropy_leaf_rows(&store).expect("leaf rows").len(), 1);
        let root = range_summary_for_workspace(&store, workspace_id, TimestampRange::ROOT)
            .expect("root summary");
        assert_eq!(root.count, 1);
    }

    #[test]
    fn sync_contribution_retract_removes_leaf_context_shareable_and_tree_path() {
        let store = store();
        let workspace_id = [9; 32];
        let fact = fact(workspace_id, 42, 1);
        let input = upsert(workspace_id, &fact, vec![[7; 32]]);
        record_sync_contribution(&store, &input, Some(&fact)).expect("upsert");

        let retract = share_fact_with_sync::ShareFactWithSync {
            workspace_id,
            owner_fact_id: fact.id,
            timestamp_ms: fact.timestamp,
            state: share_fact_with_sync::SyncShareState::Retract,
            context_have: Vec::new(),
        };
        assert!(record_sync_contribution(&store, &retract, None).expect("retract"));

        assert!(shareable_fact_rows(&store)
            .expect("shareable rows")
            .is_empty());
        assert!(negentropy_leaf_rows(&store).expect("leaf rows").is_empty());
        assert!(negentropy_context_have_rows(&store)
            .expect("context rows")
            .is_empty());
        assert!(negentropy_node_rows(&store).expect("node rows").is_empty());
        assert_eq!(
            range_summary_for_workspace(&store, workspace_id, TimestampRange::ROOT).expect("root"),
            RangeSummary::default()
        );
    }

    #[test]
    fn range_query_includes_context_only_when_requested() {
        let store = store();
        let workspace_id = [9; 32];
        let connection_id = seed_authorized_connection(&store, workspace_id);
        let context = fact(workspace_id, 10, 1);
        let owner = fact(workspace_id, 20, 2);
        store
            .write_transaction(|tx| {
                crate::core::fact_db::insert_fact_and_pending_in_tx(tx, &context)?;
                crate::core::fact_db::insert_fact_and_pending_in_tx(tx, &owner)?;
                Ok(())
            })
            .expect("persist facts");
        record_sync_contribution(
            &store,
            &upsert(workspace_id, &context, Vec::new()),
            Some(&context),
        )
        .expect("context contribution");
        record_sync_contribution(
            &store,
            &upsert(workspace_id, &owner, vec![context.id]),
            Some(&owner),
        )
        .expect("owner contribution");

        let without = shareable_facts_for_connection_range(&store, connection_id, 20, 20, false)
            .expect("without deps");
        let with = shareable_facts_for_connection_range(&store, connection_id, 20, 20, true)
            .expect("with deps");

        assert_eq!(
            without.iter().map(|fact| fact.id).collect::<Vec<_>>(),
            vec![owner.id]
        );
        assert_eq!(
            with.iter().map(|fact| fact.id).collect::<Vec<_>>(),
            vec![context.id, owner.id]
        );
    }

    #[test]
    fn received_bootstrap_request_invite_authorizes_responder_connection_sync() {
        let store = store();
        let workspace_id = [9; 32];
        let connection_id = [8; 32];
        let local_secret = [11; 32];
        let local_endpoint = crypto::x25519_public_key(&local_secret);
        let remote_endpoint = [2; 32];
        let invite =
            auth::invite_secret::fact::InviteSecretFact::scoped([21; 32], workspace_id, [22; 32]);
        let invite_fact = Fact::new(
            FactScope::Local,
            1,
            auth::invite_secret::encode::encode_fact(&invite).expect("encode invite"),
        );
        let initiator_ephemeral_private_key = [31; 32];
        let mut request = connection::request::fact::ConnectionRequestFact {
            mode: connection::request::fact::REQUEST_MODE_BOOTSTRAP,
            from_endpoint: remote_endpoint,
            to_endpoint: local_endpoint,
            nonce: [23; 32],
            dialed_addr: None,
            initiator_addr: None,
            invite_fact_id: invite.invite_fact_id.expect("invite fact id"),
            bootstrap_hash: invite.bootstrap_hash,
            invite_secret_fact_id: invite_fact.id,
            invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
            initiator_endpoint_shared_id: [0; 32],
            endpoint_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
            initiator_ephemeral_secret_fact_id: [25; 32],
            initiator_ephemeral_public_key: crypto::x25519_public_key(
                &initiator_ephemeral_private_key,
            ),
        };
        connection::request::author::sign_bootstrap_request(&mut request, &invite)
            .expect("sign request");
        let request_fact = Fact::new(
            FactScope::Global,
            2,
            connection::request::encode::seal_fact(&request, &initiator_ephemeral_private_key)
                .expect("seal request"),
        );
        let shareable = fact(workspace_id, 42, 1);

        store
            .write_transaction(|tx| {
                crate::core::fact_db::insert_fact_and_pending_in_tx(tx, &invite_fact)?;
                crate::core::fact_db::insert_fact_and_pending_in_tx(tx, &request_fact)?;
                crate::core::fact_db::insert_fact_and_pending_in_tx(tx, &shareable)?;
                Ok(())
            })
            .expect("persist facts");
        let row = endpoint_rows::local_endpoint_insert(&EndpointFact {
            endpoint: local_endpoint,
            secret: local_secret,
            signing_public_key: crypto::ed25519_public_key(&[13; 32]),
            signing_secret: [13; 32],
        });
        store
            .insert_table_values(vec![row])
            .expect("seed endpoint row");
        let row = connection::connection::connection_row(
            connection::connection::ConnectionRowFields::without_addresses(
                connection_id,
                local_endpoint,
                remote_endpoint,
                request_fact.id,
                [28; 32],
                [29; 32],
                [30; 32],
            ),
        )
        .expect("connection row");
        store
            .write_transaction(|tx| tx.insert_values_in_tx(&row).map(|_| ()))
            .expect("seed connection row");
        record_sync_contribution(
            &store,
            &upsert(workspace_id, &shareable, Vec::new()),
            Some(&shareable),
        )
        .expect("share fact");

        let summary = range_summary_for_connection(&store, connection_id, TimestampRange::ROOT)
            .expect("connection summary");
        let visible = shareable_facts_for_connection(&store, connection_id)
            .expect("visible connection facts");

        assert_eq!(summary.count, 1);
        assert_eq!(
            visible.iter().map(|fact| fact.id).collect::<Vec<_>>(),
            vec![shareable.id]
        );
    }

    fn seed_authorized_connection(store: &Db, workspace_id: FactId) -> FactId {
        let connection_id = [8; 32];
        let local_secret = [11; 32];
        let local_endpoint = crypto::x25519_public_key(&local_secret);
        let remote_endpoint = [2; 32];
        let row = endpoint_rows::local_endpoint_insert(&EndpointFact {
            endpoint: local_endpoint,
            secret: local_secret,
            signing_public_key: crypto::ed25519_public_key(&[13; 32]),
            signing_secret: [13; 32],
        });
        store
            .insert_table_values(vec![row])
            .expect("seed endpoint row");
        let connection_row = connection::connection::connection_row(
            connection::connection::ConnectionRowFields::without_addresses(
                connection_id,
                local_endpoint,
                remote_endpoint,
                [3; 32],
                [7; 32],
                [8; 32],
                [9; 32],
            ),
        )
        .expect("connection row");
        let endpoint_shared_row = endpoint_shared_rows::endpoint_shared_row(
            [5; 32],
            &EndpointSharedFact {
                created_at_ms: 1,
                workspace_id,
                user_authority_fact_id: [6; 32],
                endpoint_id: remote_endpoint,
                signing_public_key: [7; 32],
                endpoint_role: EndpointRole::Device,
                device_name: EndpointDeviceName::new("remote").expect("device name"),
                signer_id: [6; 32],
                signer_public_key: crypto::ed25519_public_key(&[17; 32]),
            },
        );
        store
            .write_transaction(|tx| {
                tx.insert_values_in_tx(&connection_row)?;
                tx.insert_values_in_tx(&endpoint_shared_row)?;
                Ok(())
            })
            .expect("seed typed rows");
        connection_id
    }
}

pub fn sync_status(store: &Db) -> Result<SyncStatus, String> {
    let mut count = 0u64;
    let mut fingerprint = [0u8; 32];
    for row in negentropy_node_rows(store)? {
        if row.level == 64 {
            count = count.saturating_add(row.summary.count);
            xor_fingerprint(&mut fingerprint, row.summary.fingerprint);
        }
    }
    Ok(SyncStatus {
        indexed_facts: count as usize,
        root_count: count,
        root_fingerprint: fingerprint,
        pending_purges: 0,
    })
}

pub fn shareable_facts_for_connection(
    store: &Db,
    connection_id: FactId,
) -> Result<Vec<Fact>, String> {
    let entries = shareable_fact_entries_for_connection(store, connection_id)?;
    let mut by_id = BTreeMap::<FactId, Fact>::new();
    for entry in entries {
        by_id.entry(entry.fact.id).or_insert(entry.fact);
    }
    let mut facts = by_id.into_values().collect::<Vec<_>>();
    facts.sort_by_key(|fact| (fact.timestamp, fact.id));
    Ok(facts)
}

pub fn range_summary_for_connection(
    store: &Db,
    connection_id: FactId,
    range: TimestampRange,
) -> Result<RangeSummary, String> {
    let mut summary = RangeSummary::default();
    for workspace_id in authorized_workspaces_for_connection(store, connection_id)? {
        let workspace_summary = range_summary_for_workspace(store, workspace_id, range)?;
        summary.count = summary.count.saturating_add(workspace_summary.count);
        xor_fingerprint(&mut summary.fingerprint, workspace_summary.fingerprint);
    }
    Ok(summary)
}

pub fn range_summary_for_workspace(
    store: &Db,
    workspace_id: FactId,
    range: TimestampRange,
) -> Result<RangeSummary, String> {
    let mut summary = RangeSummary::default();
    for (level, start_timestamp_ms) in covering_nodes(range.start, range.end) {
        if let Some(row) =
            negentropy_node_row_for_node(store, workspace_id, level, start_timestamp_ms)?
        {
            summary.count = summary.count.saturating_add(row.summary.count);
            xor_fingerprint(&mut summary.fingerprint, row.summary.fingerprint);
        }
    }
    Ok(summary)
}

#[derive(Debug, Clone)]
struct ShareableFactEntry {
    workspace_id: FactId,
    fact: Fact,
}

fn shareable_fact_entries_for_connection(
    store: &Db,
    connection_id: FactId,
) -> Result<Vec<ShareableFactEntry>, String> {
    let Some(connection) = connection_row_by_id(store, connection_id)? else {
        return Ok(Vec::new());
    };
    let Some(local_endpoint) = auth::endpoint::author::local_endpoint(store)? else {
        return Ok(Vec::new());
    };
    let Some(remote_endpoint) =
        remote_endpoint_for_connection(&connection, local_endpoint.endpoint)
    else {
        return Ok(Vec::new());
    };
    let endpoint_memberships = endpoint_memberships(store)?;
    let connection_workspaces = connection_workspaces(store, &connection)?;

    let mut facts = Vec::new();
    for row in shareable_fact_rows(store)? {
        let remote_is_member = endpoint_memberships.contains(&(row.workspace_id, remote_endpoint));
        let connection_authorizes_workspace = connection_workspaces.contains(&row.workspace_id);
        if !remote_is_member && !connection_authorizes_workspace {
            continue;
        }
        let Some(fact) = fact_for_shareable_row(store, &row)? else {
            continue;
        };
        facts.push(ShareableFactEntry {
            workspace_id: row.workspace_id,
            fact,
        });
    }
    facts.sort_by_key(|entry| (entry.fact.timestamp, entry.fact.id, entry.workspace_id));
    Ok(facts)
}

fn authorized_workspaces_for_connection(
    store: &Db,
    connection_id: FactId,
) -> Result<BTreeSet<FactId>, String> {
    let Some(connection) = connection_row_by_id(store, connection_id)? else {
        return Ok(BTreeSet::new());
    };
    let Some(local_endpoint) = auth::endpoint::author::local_endpoint(store)? else {
        return Ok(BTreeSet::new());
    };
    let Some(remote_endpoint) =
        remote_endpoint_for_connection(&connection, local_endpoint.endpoint)
    else {
        return Ok(BTreeSet::new());
    };
    let endpoint_memberships = endpoint_memberships(store)?;
    let mut workspaces = connection_workspaces(store, &connection)?;
    workspaces.extend(endpoint_memberships.into_iter().filter_map(
        |(workspace_id, endpoint_id)| (endpoint_id == remote_endpoint).then_some(workspace_id),
    ));
    Ok(workspaces)
}

pub fn shareable_facts_for_connection_range(
    store: &Db,
    connection_id: FactId,
    start_timestamp_ms: u64,
    end_timestamp_ms: u64,
    include_deps: bool,
) -> Result<Vec<Fact>, String> {
    let available = shareable_fact_entries_for_connection(store, connection_id)?;
    if !include_deps {
        let mut by_id = BTreeMap::<FactId, Fact>::new();
        for entry in available {
            if start_timestamp_ms <= entry.fact.timestamp
                && entry.fact.timestamp <= end_timestamp_ms
            {
                by_id.entry(entry.fact.id).or_insert(entry.fact);
            }
        }
        let mut facts = by_id.into_values().collect::<Vec<_>>();
        facts.sort_by_key(|fact| (fact.timestamp, fact.id));
        return Ok(facts);
    }

    let mut by_id = BTreeMap::<FactId, Fact>::new();
    let mut workspaces_by_id = BTreeMap::<FactId, BTreeSet<FactId>>::new();
    for entry in available {
        workspaces_by_id
            .entry(entry.fact.id)
            .or_default()
            .insert(entry.workspace_id);
        by_id.entry(entry.fact.id).or_insert(entry.fact);
    }
    let mut selected = BTreeSet::<FactId>::new();
    let mut pending = VecDeque::<FactId>::new();
    for fact in by_id.values() {
        if start_timestamp_ms <= fact.timestamp && fact.timestamp <= end_timestamp_ms {
            selected.insert(fact.id);
            pending.push_back(fact.id);
        }
    }

    while let Some(fact_id) = pending.pop_front() {
        let Some(workspace_ids) = workspaces_by_id.get(&fact_id) else {
            continue;
        };
        for dep_id in workspace_ids
            .iter()
            .map(|workspace_id| negentropy_context_have_for_leaf(store, *workspace_id, fact_id))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
        {
            if by_id.contains_key(&dep_id) && selected.insert(dep_id) {
                pending.push_back(dep_id);
            }
        }
    }

    let mut facts = selected
        .into_iter()
        .filter_map(|fact_id| by_id.get(&fact_id).cloned())
        .collect::<Vec<_>>();
    facts.sort_by_key(|fact| (fact.timestamp, fact.id));
    Ok(facts)
}

pub fn expand_fact_ids_with_context_for_connection(
    store: &Db,
    connection_id: FactId,
    fact_ids: &[FactId],
) -> Result<Vec<FactId>, String> {
    if fact_ids.is_empty() {
        return Ok(Vec::new());
    }
    let available = shareable_facts_for_connection(store, connection_id)?;
    let selected = fact_ids
        .iter()
        .filter_map(|fact_id| available.iter().find(|fact| fact.id == *fact_id))
        .collect::<Vec<_>>();
    let Some(start) = selected.iter().map(|fact| fact.timestamp).min() else {
        return Ok(fact_ids.to_vec());
    };
    let Some(end) = selected.iter().map(|fact| fact.timestamp).max() else {
        return Ok(fact_ids.to_vec());
    };
    let mut expanded =
        shareable_facts_for_connection_range(store, connection_id, start, end, true)?
            .into_iter()
            .map(|fact| fact.id)
            .collect::<Vec<_>>();
    expanded.sort();
    expanded.dedup();
    Ok(expanded)
}

pub fn shareable_fact_for_connection(
    store: &Db,
    connection_id: FactId,
    fact_id: FactId,
) -> Result<Option<Fact>, String> {
    Ok(shareable_facts_for_connection(store, connection_id)?
        .into_iter()
        .find(|fact| fact.id == fact_id))
}

pub fn connection_id_for_peer_or_connection(
    store: &Db,
    workspace_id: FactId,
    peer_or_connection_id: FactId,
) -> Result<Option<FactId>, String> {
    if connection_row_by_id(store, peer_or_connection_id)?.is_some() {
        return Ok(Some(peer_or_connection_id));
    }
    let Some(local_endpoint) = auth::endpoint::author::local_endpoint(store)? else {
        return Ok(None);
    };
    let endpoint_memberships = endpoint_memberships(store)?;
    for connection in connection_rows(store)? {
        let Some(remote_endpoint) =
            remote_endpoint_for_connection(&connection, local_endpoint.endpoint)
        else {
            continue;
        };
        if remote_endpoint != peer_or_connection_id {
            continue;
        }
        let connection_workspaces = connection_workspaces(store, &connection)?;
        if endpoint_memberships.contains(&(workspace_id, remote_endpoint))
            || connection_workspaces.contains(&workspace_id)
        {
            return Ok(Some(connection.connection_id));
        }
    }
    Ok(None)
}

pub fn connection_ids_for_shareable_fact(store: &Db, fact: &Fact) -> Result<Vec<FactId>, String> {
    let mut connection_ids = Vec::new();
    let workspace_ids = shareable_workspaces_for_fact(store, fact)?;
    let Some(local_endpoint) = auth::endpoint::author::local_endpoint(store)? else {
        return Ok(Vec::new());
    };
    let endpoint_memberships = endpoint_memberships(store)?;
    for connection in connection_rows(store)? {
        let Some(remote_endpoint) =
            remote_endpoint_for_connection(&connection, local_endpoint.endpoint)
        else {
            continue;
        };
        let connection_workspaces = connection_workspaces(store, &connection)?;
        if workspace_ids.iter().any(|workspace_id| {
            endpoint_memberships.contains(&(*workspace_id, remote_endpoint))
                || connection_workspaces.contains(workspace_id)
        }) {
            connection_ids.push(connection.connection_id);
        }
    }
    connection_ids.sort();
    connection_ids.dedup();
    Ok(connection_ids)
}

fn shareable_workspaces_for_fact(store: &Db, fact: &Fact) -> Result<Vec<FactId>, String> {
    if let FactScope::Scoped { kind, id } = &fact.scope {
        if kind.as_str() == "workspace" {
            return Ok(vec![*id]);
        }
    }
    let mut workspace_ids = shareable_fact_rows(store)?
        .into_iter()
        .filter(|row| row.fact_id == fact.id)
        .map(|row| row.workspace_id)
        .collect::<Vec<_>>();
    workspace_ids.sort();
    workspace_ids.dedup();
    Ok(workspace_ids)
}

fn connection_rows(
    store: &Db,
) -> Result<Vec<connection::connection::queries::ConnectionRow>, String> {
    connection::connection::queries::connection_rows(store)
}

fn connection_row_by_id(
    store: &Db,
    connection_id: FactId,
) -> Result<Option<connection::connection::queries::ConnectionRow>, String> {
    connection::connection::queries::connection_by_id(store, &connection_id)
}

fn endpoint_memberships(store: &Db) -> Result<BTreeSet<(FactId, FactId)>, String> {
    Ok(auth::endpoint_shared::queries::all_memberships(store)?
        .into_iter()
        .map(|membership| (membership.workspace_id, membership.endpoint_id))
        .collect::<BTreeSet<_>>())
}

fn connection_workspaces(
    store: &Db,
    connection: &connection::connection::queries::ConnectionRow,
) -> Result<BTreeSet<FactId>, String> {
    let mut workspace_ids = BTreeSet::new();
    let Some(invite_secret_id) = connection_invite_secret_id(store, connection)? else {
        return Ok(workspace_ids);
    };
    if let Some(invite_secret) = persisted_fact(store, &invite_secret_id)? {
        let invite = auth::invite_secret::project::decode::decode_fact(&invite_secret.bytes)
            .map_err(|_| "connection invite context is not an invite secret".to_string())?;
        if let Some(workspace_id) = invite.workspace_id {
            workspace_ids.insert(workspace_id);
        }
    }
    Ok(workspace_ids)
}

fn connection_invite_secret_id(
    store: &Db,
    connection: &connection::connection::queries::ConnectionRow,
) -> Result<Option<FactId>, String> {
    if let Some(request) = open_unified_connection_request_for_sync(store, connection)? {
        if request.mode == connection::request::fact::REQUEST_MODE_BOOTSTRAP {
            return Ok(Some(request.invite_secret_fact_id));
        }
    }
    Ok(None)
}

fn open_unified_connection_request_for_sync(
    store: &Db,
    connection: &connection::connection::queries::ConnectionRow,
) -> Result<Option<connection::request::fact::ConnectionRequestFact>, String> {
    let mut request_bytes = Vec::new();
    if let Some(request_fact) = persisted_fact(store, &connection.request_id)? {
        request_bytes.push(request_fact.bytes);
    }
    if let Some(row) = connection::request::queries::request_by_id(store, &connection.request_id)? {
        request_bytes.push(row.sealed_request_bytes);
    }
    request_bytes.sort();
    request_bytes.dedup();

    let Some(local_endpoint) = auth::endpoint::author::local_endpoint(store)? else {
        return Ok(None);
    };
    for bytes in &request_bytes {
        if let Ok(request) = connection::request::project::decode::open_fact(bytes, &local_endpoint)
        {
            return Ok(Some(request));
        }
    }

    for secret in connection_ephemeral_secrets(store)? {
        for bytes in &request_bytes {
            if let Ok(request) =
                connection::request::project::decode::open_fact_as_sender(bytes, &secret)
            {
                return Ok(Some(request));
            }
        }
    }

    Ok(None)
}

fn connection_ephemeral_secrets(
    store: &Db,
) -> Result<Vec<connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact>, String> {
    connection::ephemeral_secret::connection_ephemeral_secret_rows(store).map(|rows| {
        rows.into_iter()
            .map(
                |row| connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact {
                    owner_endpoint: row.owner_endpoint,
                    ephemeral_private_key: row.ephemeral_private_key,
                    ephemeral_public_key: row.ephemeral_public_key,
                    created_at_ms: row.created_at_ms,
                },
            )
            .collect()
    })
}

pub fn shareable_fact_rows(store: &Db) -> Result<Vec<ShareableFactRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT workspace_id, fact_id, timestamp_ms
             FROM sync_shareable_fact_rows
             ORDER BY workspace_id, fact_id
             LIMIT ?1",
        )
        .map_err(|err| format!("load shareable fact rows: {err}"))?;
    let rows = stmt
        .query_map(
            params![DEFAULT_QUERY_LIMIT as i64],
            decode_shareable_fact_row,
        )
        .map_err(|err| format!("load shareable fact rows: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode shareable fact rows: {err}"))
}

pub fn negentropy_leaf_rows(store: &Db) -> Result<Vec<NegentropyLeafRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT workspace_id, owner_fact_id, timestamp_ms, contribution_fingerprint
             FROM sync_negentropy_leaf_rows
             ORDER BY workspace_id, owner_fact_id
             LIMIT ?1",
        )
        .map_err(|err| format!("load negentropy leaf rows: {err}"))?;
    let rows = stmt
        .query_map(
            params![DEFAULT_QUERY_LIMIT as i64],
            decode_negentropy_leaf_row,
        )
        .map_err(|err| format!("load negentropy leaf rows: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode negentropy leaf rows: {err}"))
}

fn negentropy_leaf_row_for_owner(
    store: &Db,
    workspace_id: FactId,
    owner_fact_id: FactId,
) -> Result<Option<NegentropyLeafRow>, String> {
    store
        .conn()
        .query_row(
            "SELECT workspace_id, owner_fact_id, timestamp_ms, contribution_fingerprint
             FROM sync_negentropy_leaf_rows
             WHERE workspace_id = ?1 AND owner_fact_id = ?2
             LIMIT 1",
            params![workspace_id, owner_fact_id],
            decode_negentropy_leaf_row,
        )
        .optional()
        .map_err(|err| format!("load negentropy leaf row: {err}"))
}

pub fn negentropy_context_have_rows(store: &Db) -> Result<Vec<NegentropyContextHaveRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT workspace_id, owner_fact_id, context_fact_id
             FROM sync_negentropy_context_have_rows
             ORDER BY workspace_id, owner_fact_id, context_fact_id
             LIMIT ?1",
        )
        .map_err(|err| format!("load negentropy context-have rows: {err}"))?;
    let rows = stmt
        .query_map(
            params![DEFAULT_QUERY_LIMIT as i64],
            decode_negentropy_context_have_row,
        )
        .map_err(|err| format!("load negentropy context-have rows: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode negentropy context-have rows: {err}"))
}

pub fn negentropy_node_rows(store: &Db) -> Result<Vec<NegentropyNodeRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT workspace_id, level, start_timestamp_ms, count, fingerprint
             FROM sync_negentropy_node_rows
             ORDER BY workspace_id, level, start_timestamp_ms
             LIMIT ?1",
        )
        .map_err(|err| format!("load negentropy node rows: {err}"))?;
    let rows = stmt
        .query_map(
            params![DEFAULT_QUERY_LIMIT as i64],
            decode_negentropy_node_row,
        )
        .map_err(|err| format!("load negentropy node rows: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode negentropy node rows: {err}"))
}

fn negentropy_context_have_rows_for_leaf(
    store: &Db,
    workspace_id: FactId,
    owner_fact_id: FactId,
) -> Result<Vec<NegentropyContextHaveRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT workspace_id, owner_fact_id, context_fact_id
             FROM sync_negentropy_context_have_rows
             WHERE workspace_id = ?1 AND owner_fact_id = ?2
             ORDER BY context_fact_id
             LIMIT ?3",
        )
        .map_err(|err| format!("load negentropy context-have rows for leaf: {err}"))?;
    let rows = stmt
        .query_map(
            params![workspace_id, owner_fact_id, DEFAULT_QUERY_LIMIT as i64],
            decode_negentropy_context_have_row,
        )
        .map_err(|err| format!("load negentropy context-have rows for leaf: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode negentropy context-have rows for leaf: {err}"))
}

pub fn negentropy_context_have_for_leaf(
    store: &Db,
    workspace_id: FactId,
    owner_fact_id: FactId,
) -> Result<Vec<FactId>, String> {
    let mut context_ids =
        negentropy_context_have_rows_for_leaf(store, workspace_id, owner_fact_id)?
            .into_iter()
            .map(|row| row.context_fact_id)
            .collect::<Vec<_>>();
    context_ids.sort();
    context_ids.dedup();
    Ok(context_ids)
}

fn fact_for_shareable_row(store: &Db, row: &ShareableFactRow) -> Result<Option<Fact>, String> {
    let Some(fact) = persisted_fact(store, &row.fact_id)? else {
        return Ok(None);
    };
    if fact.timestamp != row.timestamp_ms {
        return Err("shareable fact timestamp does not match fact row".to_string());
    }
    match &fact.scope {
        FactScope::Global => Ok(Some(fact)),
        FactScope::Scoped { kind, id }
            if kind.as_str() == "workspace" && id == &row.workspace_id =>
        {
            Ok(Some(fact))
        }
        _ => Err("shareable fact row does not match a global or workspace-scoped fact".to_string()),
    }
}

fn remote_endpoint_for_connection(
    row: &connection::connection::queries::ConnectionRow,
    local_endpoint: FactId,
) -> Option<FactId> {
    if row.from_endpoint == local_endpoint {
        Some(row.to_endpoint)
    } else if row.to_endpoint == local_endpoint {
        Some(row.from_endpoint)
    } else {
        None
    }
}
