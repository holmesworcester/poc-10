//! File-slice connection-frame wire fact layout.

use crate::protocol::connection_frame_wire as wire;

use super::fact::ConnectionFrameFileSliceFact;

pub const TYPE_CONNECTION_FRAME_FILE_SLICE: u8 = 169;
pub const CONNECTION_FRAME_FILE_SLICE_FACT_BYTES: usize =
    wire::frame_fact_bytes::<{ wire::CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES }>();

pub fn encode_fact(fact: &ConnectionFrameFileSliceFact) -> Result<Vec<u8>, String> {
    let encoded = wire::encode_frame_fact(
        TYPE_CONNECTION_FRAME_FILE_SLICE,
        wire::CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE,
        &fact.frame,
    )?;
    if encoded.len() != CONNECTION_FRAME_FILE_SLICE_FACT_BYTES {
        return Err("connection frame file-slice fact has wrong length".to_string());
    }
    Ok(encoded)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionFrameFileSliceFact, String> {
    if bytes.len() != CONNECTION_FRAME_FILE_SLICE_FACT_BYTES {
        return Err("connection frame file-slice fact has wrong length".to_string());
    }
    let frame = wire::decode_frame_fact::<{ wire::CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES }>(
        bytes,
        TYPE_CONNECTION_FRAME_FILE_SLICE,
        wire::CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE,
    )?;
    Ok(ConnectionFrameFileSliceFact { frame })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wire::FixedSlot;

    #[test]
    fn connection_frame_file_slice_fact_roundtrips_fixed_width() {
        let frame = wire::encode_frame_bytes(
            wire::CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE,
            crate::core::wire::FixedBytes([1; 32]),
            crate::core::wire::FixedBytes([2; 24]),
            &[3; 32],
        )
        .expect("frame");
        let fact = ConnectionFrameFileSliceFact {
            frame: FixedSlot::new(&frame).expect("frame slot"),
        };

        let encoded = encode_fact(&fact).expect("encode");

        assert_eq!(encoded.len(), CONNECTION_FRAME_FILE_SLICE_FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact);
    }
}
