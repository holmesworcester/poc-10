//! Durable sync contribution rows and connection queries.
//!
//! Fact projectors record which workspace a fact may be sent through and which
//! validated context belongs to that fact's sync leaf. This module turns those
//! rows into connection-specific fact lists by checking endpoint membership,
//! connection workspace authorization, and whether the named fact still exists
//! in the core store.
//!
//! Keep sync visibility here. Fact admission belongs to projectors, and
//! connection framing belongs to `send_facts_on_connection`; callers use this
//! file to ask what a peer is allowed to learn.

use crate::core::fact_store::persisted_fact;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::store::{Store, TableName, TableRow};
use crate::protocol::{
    auth, connection,
    sync::compare::fact::{RangeSummary, TimestampRange},
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const SHAREABLE_FACT_ROWS: TableName = TableName::new("sync_shareable_fact_rows");
pub const NEGENTROPY_LEAF_ROWS: TableName = TableName::new("sync_negentropy_leaf_rows");
pub const NEGENTROPY_CONTEXT_HAVE_ROWS: TableName =
    TableName::new("sync_negentropy_context_have_rows");
pub const NEGENTROPY_NODE_ROWS: TableName = TableName::new("sync_negentropy_node_rows");

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

pub fn shareable_fact_row(row: ShareableFactRow) -> TableRow {
    let mut value = Vec::with_capacity(9);
    value.push(1);
    value.extend_from_slice(&row.timestamp_ms.to_be_bytes());
    TableRow {
        table: SHAREABLE_FACT_ROWS,
        key: shareable_fact_key(row.workspace_id, row.fact_id),
        value,
    }
}

pub fn decode_shareable_fact_row(key: &[u8], value: &[u8]) -> Result<ShareableFactRow, String> {
    if key.len() != 64 {
        return Err("shareable fact key must be workspace id plus fact id".to_string());
    }
    if value.len() != 9 || value[0] != 1 {
        return Err("invalid shareable fact row value".to_string());
    }
    Ok(ShareableFactRow {
        workspace_id: key[..32].try_into().unwrap(),
        fact_id: key[32..64].try_into().unwrap(),
        timestamp_ms: u64::from_be_bytes(value[1..9].try_into().unwrap()),
    })
}

pub(super) fn shareable_fact_key(workspace_id: FactId, fact_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&fact_id);
    key
}

pub(super) fn negentropy_leaf_row(row: NegentropyLeafRow) -> TableRow {
    let mut value = Vec::with_capacity(41);
    value.push(1);
    value.extend_from_slice(&row.timestamp_ms.to_be_bytes());
    value.extend_from_slice(&row.contribution_fingerprint);
    TableRow {
        table: NEGENTROPY_LEAF_ROWS,
        key: negentropy_leaf_key(row.workspace_id, row.owner_fact_id),
        value,
    }
}

pub(super) fn decode_negentropy_leaf_row(
    key: &[u8],
    value: &[u8],
) -> Result<NegentropyLeafRow, String> {
    if key.len() != 64 {
        return Err("negentropy leaf key must be workspace id plus owner fact id".to_string());
    }
    if value.len() != 41 || value[0] != 1 {
        return Err("invalid negentropy leaf row value".to_string());
    }
    Ok(NegentropyLeafRow {
        workspace_id: key[..32].try_into().unwrap(),
        owner_fact_id: key[32..64].try_into().unwrap(),
        timestamp_ms: u64::from_be_bytes(value[1..9].try_into().unwrap()),
        contribution_fingerprint: value[9..41].try_into().unwrap(),
    })
}

pub(super) fn negentropy_leaf_key(workspace_id: FactId, owner_fact_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&owner_fact_id);
    key
}

pub(super) fn negentropy_context_have_row(row: NegentropyContextHaveRow) -> TableRow {
    TableRow {
        table: NEGENTROPY_CONTEXT_HAVE_ROWS,
        key: negentropy_context_have_key(row.workspace_id, row.owner_fact_id, row.context_fact_id),
        value: vec![1],
    }
}

fn decode_negentropy_context_have_row(
    key: &[u8],
    value: &[u8],
) -> Result<NegentropyContextHaveRow, String> {
    if key.len() != 96 {
        return Err(
            "negentropy context-have key must be workspace id plus owner and context fact ids"
                .to_string(),
        );
    }
    if value != [1] {
        return Err("invalid negentropy context-have row value".to_string());
    }
    Ok(NegentropyContextHaveRow {
        workspace_id: key[..32].try_into().unwrap(),
        owner_fact_id: key[32..64].try_into().unwrap(),
        context_fact_id: key[64..96].try_into().unwrap(),
    })
}

pub(super) fn negentropy_context_have_key(
    workspace_id: FactId,
    owner_fact_id: FactId,
    context_fact_id: FactId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&owner_fact_id);
    key.extend_from_slice(&context_fact_id);
    key
}

pub(super) fn negentropy_node_row(row: NegentropyNodeRow) -> TableRow {
    let mut value = Vec::with_capacity(41);
    value.push(1);
    value.extend_from_slice(&row.summary.count.to_be_bytes());
    value.extend_from_slice(&row.summary.fingerprint);
    TableRow {
        table: NEGENTROPY_NODE_ROWS,
        key: negentropy_node_key(row.workspace_id, row.level, row.start_timestamp_ms),
        value,
    }
}

pub(super) fn decode_negentropy_node_row(
    key: &[u8],
    value: &[u8],
) -> Result<NegentropyNodeRow, String> {
    if key.len() != 41 {
        return Err("negentropy node key must be workspace id, level, and start".to_string());
    }
    if value.len() != 41 || value[0] != 1 {
        return Err("invalid negentropy node row value".to_string());
    }
    Ok(NegentropyNodeRow {
        workspace_id: key[..32].try_into().unwrap(),
        level: key[32],
        start_timestamp_ms: u64::from_be_bytes(key[33..41].try_into().unwrap()),
        summary: RangeSummary {
            count: u64::from_be_bytes(value[1..9].try_into().unwrap()),
            fingerprint: value[9..41].try_into().unwrap(),
        },
    })
}

pub(super) fn negentropy_node_key(
    workspace_id: FactId,
    level: u8,
    start_timestamp_ms: u64,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(41);
    key.extend_from_slice(&workspace_id);
    key.push(level);
    key.extend_from_slice(&start_timestamp_ms.to_be_bytes());
    key
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    pub indexed_facts: usize,
    pub root_count: u64,
    pub root_fingerprint: [u8; 32],
    pub pending_purges: usize,
}

pub(super) fn node_path(timestamp_ms: u64) -> impl Iterator<Item = (u8, u64)> {
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

pub(super) fn contribution_fingerprint(
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

pub(super) fn xor_fingerprint(dst: &mut [u8; 32], src: [u8; 32]) {
    for (dst, src) in dst.iter_mut().zip(src) {
        *dst ^= src;
    }
}

#[cfg(test)]
mod tests {
    use super::super::create::record_sync_contribution;
    use super::*;
    use crate::core::crypto;
    use crate::core::facts::ScopeKind;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::protocol::auth::endpoint::{fact::EndpointFact, rows as endpoint_rows};
    use crate::protocol::auth::endpoint_shared::{
        fact::{EndpointDeviceName, EndpointRole, EndpointSharedFact},
        rows as endpoint_shared_rows,
    };
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;
    use crate::protocol::sync::share_fact_with_sync;

    fn store() -> Store {
        Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
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
                crate::core::fact_store::insert_fact_and_pending_in_tx(tx, &context)?;
                crate::core::fact_store::insert_fact_and_pending_in_tx(tx, &owner)?;
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

    fn seed_authorized_connection(store: &Store, workspace_id: FactId) -> FactId {
        let connection_id = [8; 32];
        let local_secret = [11; 32];
        let local_endpoint = crypto::x25519_public_key(&local_secret);
        let remote_endpoint = [2; 32];
        let mut rows = endpoint_rows::endpoint_rows(&EndpointFact {
            endpoint: local_endpoint,
            secret: local_secret,
            signing_public_key: crypto::ed25519_public_key(&[13; 32]),
            signing_secret: [13; 32],
        });
        rows.push(
            connection::response::rows::connection_response_row(
                connection_id,
                &connection::response::fact::ConnectionResponseFact {
                    from_endpoint: local_endpoint,
                    to_endpoint: remote_endpoint,
                    request_id: [3; 32],
                    invite_secret_fact_id: [4; 32],
                    initiator_ephemeral_secret_fact_id: [5; 32],
                    responder_ephemeral_secret_fact_id: [6; 32],
                    responder_ephemeral_public_key: [7; 32],
                    handshake_hash: [8; 32],
                    connection_secret: [9; 32],
                },
            )
            .expect("connection row"),
        );
        rows.push(
            endpoint_shared_rows::endpoint_shared_row(
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
                    signature: [18; crypto::ED25519_SIGNATURE_BYTES],
                },
            )
            .expect("endpoint shared row"),
        );
        store.insert_table_rows(rows).expect("seed rows");
        connection_id
    }
}

pub fn sync_status(store: &Store) -> Result<SyncStatus, String> {
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
    store: &Store,
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
    store: &Store,
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
    store: &Store,
    workspace_id: FactId,
    range: TimestampRange,
) -> Result<RangeSummary, String> {
    let mut summary = RangeSummary::default();
    for (level, start_timestamp_ms) in covering_nodes(range.start, range.end) {
        let key = negentropy_node_key(workspace_id, level, start_timestamp_ms);
        let Some(value) = store
            .table_row(NEGENTROPY_NODE_ROWS, &key)
            .map_err(|err| format!("load negentropy node row: {err}"))?
        else {
            continue;
        };
        let row = decode_negentropy_node_row(&key, &value)?;
        summary.count = summary.count.saturating_add(row.summary.count);
        xor_fingerprint(&mut summary.fingerprint, row.summary.fingerprint);
    }
    Ok(summary)
}

#[derive(Debug, Clone)]
struct ShareableFactEntry {
    workspace_id: FactId,
    fact: Fact,
}

fn shareable_fact_entries_for_connection(
    store: &Store,
    connection_id: FactId,
) -> Result<Vec<ShareableFactEntry>, String> {
    let Some(connection) = connection_response_row(store, connection_id)? else {
        return Ok(Vec::new());
    };
    let Some(local_endpoint) = auth::endpoint::create::local_endpoint(store)? else {
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
    store: &Store,
    connection_id: FactId,
) -> Result<BTreeSet<FactId>, String> {
    let Some(connection) = connection_response_row(store, connection_id)? else {
        return Ok(BTreeSet::new());
    };
    let Some(local_endpoint) = auth::endpoint::create::local_endpoint(store)? else {
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
    store: &Store,
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
    store: &Store,
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
    store: &Store,
    connection_id: FactId,
    fact_id: FactId,
) -> Result<Option<Fact>, String> {
    Ok(shareable_facts_for_connection(store, connection_id)?
        .into_iter()
        .find(|fact| fact.id == fact_id))
}

pub fn connection_id_for_peer_or_connection(
    store: &Store,
    workspace_id: FactId,
    peer_or_connection_id: FactId,
) -> Result<Option<FactId>, String> {
    if connection_response_row(store, peer_or_connection_id)?.is_some() {
        return Ok(Some(peer_or_connection_id));
    }
    let Some(local_endpoint) = auth::endpoint::create::local_endpoint(store)? else {
        return Ok(None);
    };
    let endpoint_memberships = endpoint_memberships(store)?;
    for connection in connection_response_rows(store)? {
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

pub fn connection_ids_for_shareable_fact(
    store: &Store,
    fact: &Fact,
) -> Result<Vec<FactId>, String> {
    let mut connection_ids = Vec::new();
    let workspace_ids = shareable_workspaces_for_fact(store, fact)?;
    for workspace_id in workspace_ids {
        connection_ids.extend(connection_ids_authorized_for_workspace(
            store,
            workspace_id,
        )?);
    }
    connection_ids.sort();
    connection_ids.dedup();
    Ok(connection_ids)
}

pub fn connection_ids_authorized_for_workspace(
    store: &Store,
    workspace_id: FactId,
) -> Result<Vec<FactId>, String> {
    let mut connection_ids = Vec::new();
    let Some(local_endpoint) = auth::endpoint::create::local_endpoint(store)? else {
        return Ok(Vec::new());
    };
    let endpoint_memberships = endpoint_memberships(store)?;
    for connection in connection_response_rows(store)? {
        let Some(remote_endpoint) =
            remote_endpoint_for_connection(&connection, local_endpoint.endpoint)
        else {
            continue;
        };
        let connection_workspaces = connection_workspaces(store, &connection)?;
        if endpoint_memberships.contains(&(workspace_id, remote_endpoint))
            || connection_workspaces.contains(&workspace_id)
        {
            connection_ids.push(connection.connection_id);
        }
    }
    connection_ids.sort();
    connection_ids.dedup();
    Ok(connection_ids)
}

fn shareable_workspaces_for_fact(store: &Store, fact: &Fact) -> Result<Vec<FactId>, String> {
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

fn connection_response_rows(
    store: &Store,
) -> Result<Vec<connection::response::rows::ConnectionResponseRow>, String> {
    store
        .table_rows(connection::response::rows::CONNECTION_RESPONSE_ROWS)
        .map_err(|err| format!("load connection rows for shareable sync: {err}"))?
        .into_iter()
        .map(|(key, value)| {
            connection::response::rows::decode_connection_response_row(&key, &value)
        })
        .collect()
}

fn connection_response_row(
    store: &Store,
    connection_id: FactId,
) -> Result<Option<connection::response::rows::ConnectionResponseRow>, String> {
    store
        .table_row(
            connection::response::rows::CONNECTION_RESPONSE_ROWS,
            &connection_id,
        )
        .map_err(|err| format!("load connection row for shareable sync: {err}"))?
        .map(|value| {
            connection::response::rows::decode_connection_response_row(&connection_id, &value)
        })
        .transpose()
}

fn endpoint_memberships(store: &Store) -> Result<BTreeSet<(FactId, FactId)>, String> {
    Ok(endpoint_shared_rows(store)?
        .into_iter()
        .map(|row| (row.workspace_id, row.endpoint_id))
        .collect::<BTreeSet<_>>())
}

fn endpoint_shared_rows(
    store: &Store,
) -> Result<Vec<auth::endpoint_shared::rows::EndpointSharedRow>, String> {
    store
        .table_rows(auth::endpoint_shared::rows::ENDPOINT_SHARED_ROWS)
        .map_err(|err| format!("load endpoint memberships for shareable sync: {err}"))?
        .into_iter()
        .map(|(key, value)| auth::endpoint_shared::rows::decode_endpoint_shared_row(&key, &value))
        .collect()
}

fn connection_workspaces(
    store: &Store,
    connection: &connection::response::rows::ConnectionResponseRow,
) -> Result<BTreeSet<FactId>, String> {
    let mut workspace_ids = BTreeSet::new();
    let Some(invite_secret_id) = connection_invite_secret_id(store, connection)? else {
        return Ok(workspace_ids);
    };
    if let Some(invite_secret) = persisted_fact(store, &invite_secret_id)? {
        let invite = auth::invite::layout::decode_fact(&invite_secret.bytes)
            .map_err(|_| "connection invite context is not an invite secret".to_string())?;
        if let Some(workspace_id) = invite.workspace_id {
            workspace_ids.insert(workspace_id);
        }
    }
    Ok(workspace_ids)
}

fn connection_invite_secret_id(
    store: &Store,
    connection: &connection::response::rows::ConnectionResponseRow,
) -> Result<Option<FactId>, String> {
    if let Some(response_fact) = persisted_fact(store, &connection.connection_id)? {
        let response = connection::response::layout::decode_fact(&response_fact.bytes)
            .map_err(|_| "connection response fact row is not a connection response".to_string())?;
        return Ok(Some(response.invite_secret_fact_id));
    }
    store
        .table_row(
            connection::request::rows::CONNECTION_REQUEST_ROWS,
            &connection.request_id,
        )
        .map_err(|err| format!("load connection request row for shareable sync: {err}"))?
        .map(|value| {
            connection::request::rows::decode_connection_request_row(&connection.request_id, &value)
                .map(|row| row.invite_secret_fact_id)
        })
        .transpose()
}

pub fn shareable_fact_rows(store: &Store) -> Result<Vec<ShareableFactRow>, String> {
    store
        .table_rows(SHAREABLE_FACT_ROWS)
        .map_err(|err| format!("load shareable fact rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_shareable_fact_row(&key, &value))
        .collect()
}

pub fn negentropy_leaf_rows(store: &Store) -> Result<Vec<NegentropyLeafRow>, String> {
    store
        .table_rows(NEGENTROPY_LEAF_ROWS)
        .map_err(|err| format!("load negentropy leaf rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_negentropy_leaf_row(&key, &value))
        .collect()
}

pub(super) fn negentropy_leaf_row_for_owner(
    store: &Store,
    workspace_id: FactId,
    owner_fact_id: FactId,
) -> Result<Option<NegentropyLeafRow>, String> {
    let key = negentropy_leaf_key(workspace_id, owner_fact_id);
    store
        .table_row(NEGENTROPY_LEAF_ROWS, &key)
        .map_err(|err| format!("load negentropy leaf row: {err}"))?
        .map(|value| decode_negentropy_leaf_row(&key, &value))
        .transpose()
}

pub fn negentropy_context_have_rows(
    store: &Store,
) -> Result<Vec<NegentropyContextHaveRow>, String> {
    store
        .table_rows(NEGENTROPY_CONTEXT_HAVE_ROWS)
        .map_err(|err| format!("load negentropy context-have rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_negentropy_context_have_row(&key, &value))
        .collect()
}

pub fn negentropy_node_rows(store: &Store) -> Result<Vec<NegentropyNodeRow>, String> {
    store
        .table_rows(NEGENTROPY_NODE_ROWS)
        .map_err(|err| format!("load negentropy node rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_negentropy_node_row(&key, &value))
        .collect()
}

pub(super) fn negentropy_context_have_rows_for_leaf(
    store: &Store,
    workspace_id: FactId,
    owner_fact_id: FactId,
) -> Result<Vec<NegentropyContextHaveRow>, String> {
    let prefix = negentropy_leaf_key(workspace_id, owner_fact_id);
    store
        .table_rows_with_key_prefix(NEGENTROPY_CONTEXT_HAVE_ROWS, &prefix, usize::MAX)
        .map_err(|err| format!("load negentropy context-have rows for leaf: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_negentropy_context_have_row(&key, &value))
        .collect()
}

pub fn negentropy_context_have_for_leaf(
    store: &Store,
    workspace_id: FactId,
    owner_fact_id: FactId,
) -> Result<Vec<FactId>, String> {
    let prefix = negentropy_leaf_key(workspace_id, owner_fact_id);
    let mut context_ids = store
        .table_rows_with_key_prefix(NEGENTROPY_CONTEXT_HAVE_ROWS, &prefix, usize::MAX)
        .map_err(|err| format!("load negentropy context-have rows for leaf: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_negentropy_context_have_row(&key, &value))
        .map(|row| row.map(|row| row.context_fact_id))
        .collect::<Result<Vec<_>, _>>()?;
    context_ids.sort();
    context_ids.dedup();
    Ok(context_ids)
}

fn fact_for_shareable_row(store: &Store, row: &ShareableFactRow) -> Result<Option<Fact>, String> {
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
    row: &connection::response::rows::ConnectionResponseRow,
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
