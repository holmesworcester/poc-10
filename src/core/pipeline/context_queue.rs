//! Pending context-change queue.

use super::context_codec::{
    scope_key, selected_bytes, selected_fact_id, selected_role, selected_scope, selected_selector,
    selected_u64,
};
use crate::core::context::{ContextNeed, ContextOffer, ContextSetDelta, Role, Selector};
use crate::core::facts::{FactId, FactScope};
use crate::core::pipeline::PENDING_CONTEXT_CHANGES;
use crate::core::schema_dsl::ColumnType;
use crate::core::store::{ColumnValue, SelectColumn, SelectedRow, Store};

const CONTEXT_CHANGE_NEED: u64 = 0;
const CONTEXT_CHANGE_OFFER: u64 = 1;

const PENDING_CONTEXT_CHANGE_COLUMNS: &[SelectColumn] = &[
    SelectColumn {
        name: "owner",
        ty: ColumnType::Bytes { len: Some(32) },
    },
    SelectColumn {
        name: "change_kind",
        ty: ColumnType::U64,
    },
    SelectColumn {
        name: "role",
        ty: ColumnType::Text,
    },
    SelectColumn {
        name: "scope_key",
        ty: ColumnType::Bytes { len: None },
    },
    SelectColumn {
        name: "selector",
        ty: ColumnType::Bytes { len: None },
    },
];

pub(super) struct PendingContextChange {
    pub(super) owner: FactId,
    change_kind: u64,
    pub(super) role: Role,
    pub(super) scope_key: Vec<u8>,
    pub(super) scope: FactScope,
    pub(super) selector: Selector,
}

impl PendingContextChange {
    pub(super) fn add_to_delta(&self, delta: &mut ContextSetDelta) {
        match self.change_kind {
            CONTEXT_CHANGE_NEED => delta.added_needs.push(ContextNeed {
                owner: self.owner,
                role: self.role.clone(),
                scope: self.scope.clone(),
                selector: self.selector.clone(),
            }),
            CONTEXT_CHANGE_OFFER => delta.added_offers.push(ContextOffer {
                owner: self.owner,
                role: self.role.clone(),
                scope: self.scope.clone(),
                selector: self.selector.clone(),
            }),
            _ => unreachable!("pending context changes are validated on read"),
        }
    }
}

/// Insert every added need and offer in `delta` into the pending context queue.
pub(super) fn insert_pending_context_changes_in_tx(
    store: &Store,
    delta: &ContextSetDelta,
) -> rusqlite::Result<usize> {
    let mut inserted = 0usize;
    for need in &delta.added_needs {
        if insert_pending_context_change_in_tx(
            store,
            &need.owner,
            CONTEXT_CHANGE_NEED,
            &need.role,
            &need.scope,
            &need.selector,
        )? {
            inserted += 1;
        }
    }
    for offer in &delta.added_offers {
        if insert_pending_context_change_in_tx(
            store,
            &offer.owner,
            CONTEXT_CHANGE_OFFER,
            &offer.role,
            &offer.scope,
            &offer.selector,
        )? {
            inserted += 1;
        }
    }
    Ok(inserted)
}

pub(super) fn pending_context_change_batch(
    store: &Store,
    limit: usize,
) -> Result<Vec<PendingContextChange>, String> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    store
        .select_only(
            r#"
            SELECT owner, change_kind, role, scope_key, selector
            FROM pending_context_changes
            ORDER BY owner, change_kind, role, scope_key, selector
            LIMIT :limit
            "#,
            &[PENDING_CONTEXT_CHANGES],
            &[(":limit", ColumnValue::U64(limit as u64))],
            PENDING_CONTEXT_CHANGE_COLUMNS,
        )
        .map_err(|err| format!("load pending context changes: {err}"))?
        .into_iter()
        .map(selected_pending_context_change)
        .collect()
}

pub(super) fn delete_pending_context_change_in_tx(
    store: &Store,
    change: &PendingContextChange,
) -> rusqlite::Result<usize> {
    store.delete_typed_rows_where_in_tx(
        PENDING_CONTEXT_CHANGES,
        &[
            ("owner", ColumnValue::Bytes(&change.owner)),
            ("change_kind", ColumnValue::U64(change.change_kind)),
            ("role", ColumnValue::Text(change.role.as_str())),
            ("scope_key", ColumnValue::Bytes(&change.scope_key)),
            ("selector", ColumnValue::Bytes(change.selector.as_bytes())),
        ],
    )
}

fn selected_pending_context_change(row: SelectedRow) -> Result<PendingContextChange, String> {
    let change_kind = selected_u64(&row, "change_kind")?;
    if !matches!(change_kind, CONTEXT_CHANGE_NEED | CONTEXT_CHANGE_OFFER) {
        return Err(format!("invalid pending context change kind {change_kind}"));
    }
    let scope_key = selected_bytes(&row, "scope_key")?.to_vec();
    Ok(PendingContextChange {
        owner: selected_fact_id(&row, "owner")?,
        change_kind,
        role: selected_role(&row)?,
        scope: selected_scope(&row)?,
        scope_key,
        selector: selected_selector(&row)?,
    })
}

fn insert_pending_context_change_in_tx(
    store: &Store,
    owner: &FactId,
    change_kind: u64,
    role: &Role,
    scope: &FactScope,
    selector: &Selector,
) -> rusqlite::Result<bool> {
    store.insert_typed_row_in_tx(
        PENDING_CONTEXT_CHANGES,
        &[
            ("owner", ColumnValue::Bytes(owner)),
            ("change_kind", ColumnValue::U64(change_kind)),
            ("role", ColumnValue::Text(role.as_str())),
            ("scope_key", ColumnValue::Bytes(&scope_key(scope))),
            ("selector", ColumnValue::Bytes(selector.as_bytes())),
        ],
    )
}
