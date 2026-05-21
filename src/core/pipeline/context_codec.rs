//! Encoding and decoding helpers for context-related SQL rows.

use crate::core::facts::{FactScope, ScopeKind};
#[cfg(test)]
use crate::core::schema::CONTEXT_EDGES;
#[cfg(test)]
use crate::core::store::TableRow;
#[cfg(test)]
use crate::core::wire::Writer;
use crate::core::wire::{Reader, WireError};
#[cfg(test)]
use crate::core::{
    context::{scope_key, ContextNeed, ContextOffer, Role, Selector},
    facts::FactId,
};

pub(super) const CONTEXT_NEED_DIRECTION: &str = "need";
pub(super) const CONTEXT_OFFER_DIRECTION: &str = "offer";

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

pub(super) fn decode_scope_key(bytes: &[u8]) -> Result<FactScope, String> {
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
