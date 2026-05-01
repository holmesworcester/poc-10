//! Wire codec for the `file_slice` event (type 46).
//!
//! Variable-length wire format. Format:
//!
//! ```text
//! [0]                    type_code = 46
//! [1..9]                 created_at_ms (u64 LE)
//! [9..41]                workspace_id (32 bytes)
//! [41..73]               file_event_id (32 bytes; dep)
//! [73..77]               slice_index (u32 LE)
//! [77..109]              slice_hash (32 bytes; blake3 of slice_bytes)
//! [109..141]             signed_by (32 bytes)
//! [141]                  signer_type (u8)
//! [142..206]             signature (64 bytes)
//! [206..210]             slice_bytes_len (u32 LE)
//! [210..210+len]         slice_bytes (raw plaintext)
//! ```
//!
//! Total size depends on slice_bytes. The pipeline enforces
//! `EVENT_MAX_BLOB_BYTES` (1 MiB) at the substrate boundary.

use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_FILE_SLICE};

/// Fixed prefix size before the variable-length `slice_bytes`.
pub const FILE_SLICE_FIXED_PREFIX_BYTES: usize =
    1 + 8 + 32 + 32 + 4 + 32 + 32 + 1 + 64 + 4;
// 210

/// Maximum bytes of plaintext per slice (chosen so the full event blob fits
/// well below the 1 MiB substrate cap, leaving room for envelope overhead).
pub const MAX_SLICE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSliceEvent {
    pub created_at_ms: u64,
    pub workspace_id: [u8; 32],
    /// Event id of the parent `file` event (32 bytes).
    pub file_event_id: [u8; 32],
    pub slice_index: u32,
    /// Blake3 hash of `slice_bytes` for self-validating per-slice integrity.
    pub slice_hash: [u8; 32],
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
    pub slice_bytes: Vec<u8>,
}

pub const FILE_SLICE_FIELDS: &[&str] = &["workspace_id", "file_event_id", "signed_by"];

impl super::super::Describe for FileSliceEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "file_event_id",
                super::super::short_id_b64(&self.file_event_id),
            ),
            ("slice_index", self.slice_index.to_string()),
            ("data", format!("{} bytes", self.slice_bytes.len())),
        ]
    }
}

pub fn parse_file_slice(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < FILE_SLICE_FIXED_PREFIX_BYTES {
        return Err(EventError::TooShort {
            expected: FILE_SLICE_FIXED_PREFIX_BYTES,
            actual: blob.len(),
        });
    }
    let type_code = blob[0];
    if type_code != EVENT_TYPE_FILE_SLICE {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_FILE_SLICE,
            actual: type_code,
        });
    }
    let mut off = 1usize;

    let created_at_ms = u64::from_le_bytes(blob[off..off + 8].try_into().unwrap());
    off += 8;

    let mut workspace_id = [0u8; 32];
    workspace_id.copy_from_slice(&blob[off..off + 32]);
    off += 32;

    let mut file_event_id = [0u8; 32];
    file_event_id.copy_from_slice(&blob[off..off + 32]);
    off += 32;

    let slice_index = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
    off += 4;

    let mut slice_hash = [0u8; 32];
    slice_hash.copy_from_slice(&blob[off..off + 32]);
    off += 32;

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off..off + 32]);
    off += 32;

    let signer_type = blob[off];
    off += 1;

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off..off + 64]);
    off += 64;

    let slice_bytes_len = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap()) as usize;
    off += 4;

    if slice_bytes_len > MAX_SLICE_BYTES {
        return Err(EventError::ContentTooLong(slice_bytes_len));
    }
    if off + slice_bytes_len != blob.len() {
        return Err(EventError::TrailingData {
            expected: off + slice_bytes_len,
            actual: blob.len(),
        });
    }
    let slice_bytes = blob[off..off + slice_bytes_len].to_vec();

    Ok(ParsedEvent::FileSlice(FileSliceEvent {
        created_at_ms,
        workspace_id,
        file_event_id,
        slice_index,
        slice_hash,
        signed_by,
        signer_type,
        signature,
        slice_bytes,
    }))
}

pub fn encode_file_slice(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let s = match event {
        ParsedEvent::FileSlice(s) => s,
        _ => return Err(EventError::WrongVariant),
    };

    if s.slice_bytes.len() > MAX_SLICE_BYTES {
        return Err(EventError::ContentTooLong(s.slice_bytes.len()));
    }
    let total_size = FILE_SLICE_FIXED_PREFIX_BYTES + s.slice_bytes.len();
    if total_size > super::super::EVENT_MAX_BLOB_BYTES {
        return Err(EventError::ContentTooLong(total_size));
    }
    let mut out = Vec::with_capacity(total_size);
    out.push(EVENT_TYPE_FILE_SLICE);
    out.extend_from_slice(&s.created_at_ms.to_le_bytes());
    out.extend_from_slice(&s.workspace_id);
    out.extend_from_slice(&s.file_event_id);
    out.extend_from_slice(&s.slice_index.to_le_bytes());
    out.extend_from_slice(&s.slice_hash);
    out.extend_from_slice(&s.signed_by);
    out.push(s.signer_type);
    out.extend_from_slice(&s.signature);
    out.extend_from_slice(&(s.slice_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&s.slice_bytes);
    Ok(out)
}

pub static FILE_SLICE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_FILE_SLICE,
    type_name: "file_slice",
    projection_table: "file_slices",
    share_scope: ShareScope::Shared,
    dep_fields: &["file_event_id", "signed_by"],
    dep_field_type_codes: &[&[crate::event_modules::EVENT_TYPE_FILE], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_file_slice,
    encode: encode_file_slice,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_slice_codec_roundtrip() {
        let s = FileSliceEvent {
            created_at_ms: 1000,
            workspace_id: [0x11; 32],
            file_event_id: [0x22; 32],
            slice_index: 3,
            slice_hash: [0x33; 32],
            signed_by: [0x44; 32],
            signer_type: 5,
            signature: [0x55; 64],
            slice_bytes: vec![0xAA; 1024],
        };
        let blob = encode_file_slice(&ParsedEvent::FileSlice(s.clone())).unwrap();
        let parsed = parse_file_slice(&blob).unwrap();
        match parsed {
            ParsedEvent::FileSlice(decoded) => assert_eq!(decoded, s),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_file_slice_codec_max_size() {
        let s = FileSliceEvent {
            created_at_ms: 1000,
            workspace_id: [0; 32],
            file_event_id: [0; 32],
            slice_index: 0,
            slice_hash: [0; 32],
            signed_by: [0; 32],
            signer_type: 0,
            signature: [0; 64],
            slice_bytes: vec![0u8; MAX_SLICE_BYTES],
        };
        let blob = encode_file_slice(&ParsedEvent::FileSlice(s.clone())).unwrap();
        assert_eq!(blob.len(), FILE_SLICE_FIXED_PREFIX_BYTES + MAX_SLICE_BYTES);
        let parsed = parse_file_slice(&blob).unwrap();
        assert!(matches!(parsed, ParsedEvent::FileSlice(_)));
    }

    #[test]
    fn test_file_slice_codec_oversize_rejects() {
        let s = FileSliceEvent {
            created_at_ms: 0,
            workspace_id: [0; 32],
            file_event_id: [0; 32],
            slice_index: 0,
            slice_hash: [0; 32],
            signed_by: [0; 32],
            signer_type: 0,
            signature: [0; 64],
            slice_bytes: vec![0u8; MAX_SLICE_BYTES + 1],
        };
        let err = encode_file_slice(&ParsedEvent::FileSlice(s)).unwrap_err();
        assert!(matches!(err, EventError::ContentTooLong(_)));
    }
}
