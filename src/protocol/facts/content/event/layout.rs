//! Content-event fact layout.
//!
//! The fact has a fixed header (tag + workspace_id + timestamp + payload_len)
//! followed by exactly `payload_len` opaque bytes. The payload is
//! length-prefixed so the canonical encoding is self-describing on decode.

use crate::core::wire;

use super::fact::ContentEventFact;

pub const TYPE_CONTENT_EVENT: u8 = 41;
pub const FACT_PREFIX_BYTES: usize = 1 + 32 + 8 + 4;

pub fn encode_fact(fact: &ContentEventFact) -> Result<Vec<u8>, String> {
    let payload_len_u32: u32 = fact
        .payload
        .len()
        .try_into()
        .map_err(|_| "content payload exceeds u32 length".to_string())?;
    let mut out = wire::Writer::with_capacity(FACT_PREFIX_BYTES + fact.payload.len());
    out.u8(TYPE_CONTENT_EVENT);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.timestamp);
    out.u32be(payload_len_u32);
    out.bytes(&fact.payload);
    Ok(out.finish())
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentEventFact, String> {
    if bytes.len() < FACT_PREFIX_BYTES {
        return Err("content event fact is shorter than its header".to_string());
    }
    let mut reader = wire::Reader::new(bytes);
    let tag = reader.u8().map_err(wire_err)?;
    if tag != TYPE_CONTENT_EVENT {
        return Err("expected content event fact".to_string());
    }
    let workspace_id = reader.array().map_err(wire_err)?;
    let timestamp = reader.u64be().map_err(wire_err)?;
    let payload_len = reader.u32be().map_err(wire_err)? as usize;
    if bytes.len() != FACT_PREFIX_BYTES + payload_len {
        return Err("content event fact length does not match declared payload".to_string());
    }
    let payload = reader.bytes(payload_len).map_err(wire_err)?.to_vec();
    reader.finish().map_err(wire_err)?;
    Ok(ContentEventFact {
        workspace_id,
        timestamp,
        payload,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ContentEventFact {
        ContentEventFact {
            workspace_id: [3; 32],
            timestamp: 12345,
            payload: vec![0xab, 0xcd, 0xef],
        }
    }

    #[test]
    fn content_event_roundtrips_with_payload() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), FACT_PREFIX_BYTES + 3);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }

    #[test]
    fn rejects_trailing_or_truncated_bytes() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        bytes.push(0);
        assert!(decode_fact(&bytes).is_err());

        let mut short = encode_fact(&fact()).expect("encode");
        short.pop();
        assert!(decode_fact(&short).is_err());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        bytes[0] = TYPE_CONTENT_EVENT.wrapping_add(1);
        assert!(decode_fact(&bytes).is_err());
    }
}
