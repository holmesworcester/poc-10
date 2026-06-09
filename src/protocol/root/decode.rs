use crate::core::wire;

use super::encode::{ROOT_BYTES, TYPE_ROOT};
use super::fact::{validate_refs, RootFact, RootRef, MAX_REFS};

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = RootFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<RootFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader.expect_len(ROOT_BYTES).map_err(wire_err)?;
    reader.expect_u8(TYPE_ROOT).map_err(wire_err)?;
    let family = reader.u32be().map_err(wire_err)?;
    let version = reader.u32be().map_err(wire_err)?;
    let created_at_ms = reader.u64be().map_err(wire_err)?;
    let mut refs = Vec::new();
    let mut seen_empty = false;

    for _ in 0..MAX_REFS {
        let edge = RootRef {
            role: reader.u32be().map_err(wire_err)?,
            index: reader.u32be().map_err(wire_err)?,
            target_fact_id: reader.array().map_err(wire_err)?,
        };
        if edge.is_empty() {
            seen_empty = true;
        } else {
            if seen_empty {
                return Err("root has non-empty ref after empty slot".to_string());
            }
            refs.push(edge);
        }
    }

    reader.finish().map_err(wire_err)?;
    validate_refs(&refs)?;
    Ok(RootFact {
        family,
        version,
        created_at_ms,
        refs,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::root::encode::ROOT_REF_BYTES;

    fn root() -> RootFact {
        RootFact {
            family: 1,
            version: 1,
            created_at_ms: 10,
            refs: vec![
                RootRef::new(crate::protocol::root::roles::WORKSPACE, 0, [1; 32]).unwrap(),
                RootRef::new(crate::protocol::root::roles::CONTENT, 0, [2; 32]).unwrap(),
            ],
        }
    }

    #[test]
    fn root_roundtrips_fixed_width() {
        let encoded = crate::protocol::root::encode::encode_fact(&root()).expect("encode root");
        assert_eq!(encoded.len(), ROOT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode root"), root());
    }

    #[test]
    fn rejects_non_empty_ref_after_empty_slot() {
        let mut encoded = crate::protocol::root::encode::encode_fact(&root()).expect("encode root");
        let second_ref_offset = 1 + 4 + 4 + 8 + ROOT_REF_BYTES;
        let third_ref_offset = second_ref_offset + ROOT_REF_BYTES;
        encoded[second_ref_offset..second_ref_offset + ROOT_REF_BYTES].fill(0);
        encoded[third_ref_offset..third_ref_offset + 4]
            .copy_from_slice(&crate::protocol::root::roles::TARGET.to_be_bytes());
        encoded[third_ref_offset + 8..third_ref_offset + ROOT_REF_BYTES].fill(9);

        assert!(decode_fact(&encoded).is_err());
    }

    #[test]
    fn rejects_duplicate_role_index() {
        let root = RootFact {
            refs: vec![
                RootRef::new(crate::protocol::root::roles::CONTENT, 0, [1; 32]).unwrap(),
                RootRef::new(crate::protocol::root::roles::CONTENT, 0, [2; 32]).unwrap(),
            ],
            ..root()
        };
        assert!(crate::protocol::root::encode::encode_fact(&root).is_err());
    }
}
