//! Encoding and decoding helpers for context-related SQL rows.

#[cfg(test)]
use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::context::{Role, Selector};
use crate::core::facts::{FactId, FactScope, ScopeKind};
#[cfg(test)]
use crate::core::pipeline::CONTEXT_EDGES;
use crate::core::schema_dsl::ColumnType;
#[cfg(test)]
use crate::core::store::TableRow;
use crate::core::store::{SelectColumn, SelectedRow, SelectedValue};
use crate::core::wire::{Reader, WireError, Writer};

pub(super) const CONTEXT_NEED_DIRECTION: &str = "need";
pub(super) const CONTEXT_OFFER_DIRECTION: &str = "offer";

pub(super) const CONTEXT_EDGE_VALUE_COLUMNS: &[SelectColumn] = &[
    SelectColumn {
        name: "owner",
        ty: ColumnType::Bytes { len: Some(32) },
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

pub(crate) fn scope_key(scope: &FactScope) -> Vec<u8> {
    let mut out = Writer::new();
    encode_scope(&mut out, scope);
    out.finish()
}

pub(super) fn selected_fact_id(row: &SelectedRow, name: &str) -> Result<FactId, String> {
    selected_bytes(row, name)?
        .try_into()
        .map_err(|_| format!("context SQL column {name} is not a fact id"))
}

pub(super) fn selected_role(row: &SelectedRow) -> Result<Role, String> {
    match row.get("role") {
        Some(SelectedValue::Text(value)) => Role::new(value.clone()),
        Some(_) => Err("context SQL column role is not text".to_string()),
        None => Err("context SQL did not return column role".to_string()),
    }
}

pub(super) fn selected_scope(row: &SelectedRow) -> Result<FactScope, String> {
    decode_scope_key(selected_bytes(row, "scope_key")?)
}

pub(super) fn selected_selector(row: &SelectedRow) -> Result<Selector, String> {
    Ok(Selector::from_bytes(
        selected_bytes(row, "selector")?.to_vec(),
    ))
}

pub(super) fn selected_u64(row: &SelectedRow, name: &str) -> Result<u64, String> {
    match row.get(name) {
        Some(SelectedValue::U64(value)) => Ok(*value),
        Some(_) => Err(format!("context SQL column {name} is not u64")),
        None => Err(format!("context SQL did not return column {name}")),
    }
}

pub(super) fn selected_bytes<'a>(row: &'a SelectedRow, name: &str) -> Result<&'a [u8], String> {
    match row.get(name) {
        Some(SelectedValue::Bytes(bytes)) => Ok(bytes),
        Some(_) => Err(format!("context SQL column {name} is not bytes")),
        None => Err(format!("context SQL did not return column {name}")),
    }
}

#[cfg(test)]
pub(crate) fn context_need_row(need: &ContextNeed) -> TableRow {
    TableRow {
        table: CONTEXT_EDGES,
        key: typed_context_key(
            &need.owner,
            CONTEXT_NEED_DIRECTION,
            &need.role,
            &need.scope,
            &need.selector,
        ),
        value: Vec::new(),
    }
}

#[cfg(test)]
pub(crate) fn context_offer_row(offer: &ContextOffer) -> TableRow {
    TableRow {
        table: CONTEXT_EDGES,
        key: typed_context_key(
            &offer.owner,
            CONTEXT_OFFER_DIRECTION,
            &offer.role,
            &offer.scope,
            &offer.selector,
        ),
        value: Vec::new(),
    }
}

#[cfg(test)]
fn typed_context_key(
    owner: &FactId,
    direction: &str,
    role: &Role,
    scope: &FactScope,
    selector: &Selector,
) -> Vec<u8> {
    encoded_row(|key| {
        key.fixed(owner);
        key.string_u32be(direction)
            .expect("context direction fits u32");
        key.string_u32be(role.as_str())
            .expect("context role fits u32");
        key.bytes_u32be(&scope_key(scope))
            .expect("scope key fits u32");
        key.bytes_u32be(selector.as_bytes())
            .expect("selector fits u32");
    })
}

fn encode_scope(out: &mut Writer, scope: &FactScope) {
    match scope {
        FactScope::Global => out.u8(0),
        FactScope::Local => out.u8(1),
        FactScope::Scoped { kind, id } => {
            out.u8(2);
            out.string_u16be(kind.as_str())
                .expect("scope kind fits u16");
            out.fixed(id);
        }
    }
}

fn decode_scope(reader: &mut Reader<'_>) -> Result<FactScope, String> {
    match reader.u8().row()? {
        0 => Ok(FactScope::Global),
        1 => Ok(FactScope::Local),
        2 => {
            let kind = ScopeKind::new(reader.string_u16be().row()?)?;
            let id = reader.array::<32>().row()?;
            Ok(FactScope::Scoped { kind, id })
        }
        other => Err(format!("invalid fact scope tag {other}")),
    }
}

fn decode_scope_key(bytes: &[u8]) -> Result<FactScope, String> {
    let mut reader = Reader::new(bytes);
    let scope = decode_scope(&mut reader)?;
    reader.finish().row()?;
    Ok(scope)
}

#[cfg(test)]
fn encoded_row(write: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut out = Writer::new();
    write(&mut out);
    out.finish()
}

trait RowWireResult<T> {
    fn row(self) -> Result<T, String>;
}

impl<T> RowWireResult<T> for Result<T, WireError> {
    fn row(self) -> Result<T, String> {
        self.map_err(|err| format!("invalid encoded row: {err}"))
    }
}
