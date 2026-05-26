//! File-slice connection-frame receive fact layout.

use crate::protocol::connection::frame::wire;

use super::fact::ConnectionFrameFileSliceFact;

pub const TYPE_CONNECTION_FRAME_FILE_SLICE: u8 = 169;
pub const CONNECTION_FRAME_FILE_SLICE_FACT_BYTES: usize =
    wire::received_frame_fact_bytes::<{ wire::CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES }>();

pub fn encode_fact(fact: &ConnectionFrameFileSliceFact) -> Result<Vec<u8>, String> {
    let encoded = wire::encode_received_frame_fact(
        TYPE_CONNECTION_FRAME_FILE_SLICE,
        wire::CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE,
        &fact.origin_addr,
        fact.received_at_local_ms,
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
    let (origin_addr, received_at_local_ms, frame) =
        wire::decode_received_frame_fact::<{ wire::CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES }>(
            bytes,
            TYPE_CONNECTION_FRAME_FILE_SLICE,
            wire::CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE,
        )?;
    Ok(ConnectionFrameFileSliceFact {
        origin_addr,
        received_at_local_ms,
        frame,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wire::FixedSlot;
    use crate::protocol::connection::fact_receipt::fact::OriginAddr;

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
            origin_addr: OriginAddr::new(b"127.0.0.1:41001").expect("origin"),
            received_at_local_ms: 123,
            frame: FixedSlot::new(&frame).expect("frame slot"),
        };

        let encoded = encode_fact(&fact).expect("encode");

        assert_eq!(encoded.len(), CONNECTION_FRAME_FILE_SLICE_FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact);
    }
}
