//! Fixed-width layout for content-file-slice facts with one padded ciphertext
//! slot.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   file_id (32)
//!   slice_index (u32be)
//!   ciphertext (FixedSlot<FILE_SLICE_CIPHERTEXT_BYTES>)

use crate::core::wire;
use crate::core::wire::FixedLayout;

use super::fact::{ContentFileSliceFact, FILE_SLICE_CIPHERTEXT_BYTES};

pub const TYPE_CONTENT_FILE_SLICE: u8 = 55;
pub const FACT_PREFIX_BYTES: usize = 1 + 32 + 8 + 32 + 4;
pub const CONTENT_FILE_SLICE_BYTES: usize =
    FACT_PREFIX_BYTES + wire::FixedSlot::<FILE_SLICE_CIPHERTEXT_BYTES>::LEN;

pub fn encode_fact(fact: &ContentFileSliceFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_FILE_SLICE_BYTES);
    out.u8(TYPE_CONTENT_FILE_SLICE);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.file_id);
    out.u32be(fact.slice_index);
    out.fixed_slot_value(&fact.ciphertext).map_err(wire_err)?;
    out.finish_exact(CONTENT_FILE_SLICE_BYTES).map_err(wire_err)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentFileSliceFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader
        .expect_len(CONTENT_FILE_SLICE_BYTES)
        .map_err(wire_err)?;
    let tag = reader.u8().map_err(wire_err)?;
    if tag != TYPE_CONTENT_FILE_SLICE {
        return Err("expected content file slice fact".to_string());
    }
    let workspace_id = reader.array().map_err(wire_err)?;
    let created_at_ms = reader.u64be().map_err(wire_err)?;
    let file_id = reader.array().map_err(wire_err)?;
    let slice_index = reader.u32be().map_err(wire_err)?;
    let ciphertext = reader
        .fixed_slot_value::<FILE_SLICE_CIPHERTEXT_BYTES>()
        .map_err(wire_err)?;
    reader.finish().map_err(wire_err)?;
    Ok(ContentFileSliceFact {
        workspace_id,
        created_at_ms,
        file_id,
        slice_index,
        ciphertext,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on_big_stack<F>(f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    fn fact() -> ContentFileSliceFact {
        ContentFileSliceFact {
            workspace_id: [1; 32],
            created_at_ms: 4242,
            file_id: [2; 32],
            slice_index: 3,
            ciphertext: crate::protocol::content::file_slice::fact::FileSliceCiphertext::new(
                &[0xaa; 128],
            )
            .expect("ciphertext"),
        }
    }

    #[test]
    fn content_file_slice_roundtrips_with_ciphertext() {
        on_big_stack(|| {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), CONTENT_FILE_SLICE_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        });
    }

    #[test]
    fn rejects_wrong_tag() {
        on_big_stack(|| {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[0] = TYPE_CONTENT_FILE_SLICE.wrapping_add(1);
            assert!(decode_fact(&encoded).is_err());
        });
    }

    #[test]
    fn rejects_wrong_length() {
        on_big_stack(|| {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded.push(0);
            assert!(decode_fact(&encoded).is_err());
        });
    }
}
