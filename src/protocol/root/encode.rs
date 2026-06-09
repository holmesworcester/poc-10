use crate::core::wire;

use super::fact::{validate_refs, RootFact, RootRef, MAX_REFS};

pub const TYPE_ROOT: u8 = 180;
pub const ROOT_REF_BYTES: usize = 4 + 4 + 32;
pub const ROOT_BYTES: usize = 1 + 4 + 4 + 8 + MAX_REFS * ROOT_REF_BYTES;

pub fn encode_fact(root: &RootFact) -> Result<Vec<u8>, String> {
    validate_refs(&root.refs)?;
    let mut out = wire::Writer::with_capacity(ROOT_BYTES);
    out.u8(TYPE_ROOT);
    out.u32be(root.family);
    out.u32be(root.version);
    out.u64be(root.created_at_ms);

    for slot in 0..MAX_REFS {
        let edge = root.refs.get(slot).copied().unwrap_or(RootRef::EMPTY);
        out.u32be(edge.role);
        out.u32be(edge.index);
        out.fixed(&edge.target_fact_id);
    }

    out.finish_exact(ROOT_BYTES).map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
