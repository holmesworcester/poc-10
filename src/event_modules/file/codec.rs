//! Wire codec for the `file` event (type 45).
//!
//! Variable-length wire format keeps `bao_outboard` and `file_name` flexible
//! without needing a giant fixed slot. Format:
//!
//! ```text
//! [0]                    type_code = 45
//! [1..9]                 created_at_ms (u64 LE)
//! [9..41]                workspace_id (32 bytes)
//! [41..73]               content_hash (32 bytes; bao root over plaintext)
//! [73..81]               size_bytes (u64 LE)
//! [81..85]               slice_count (u32 LE)
//! [85..117]              signed_by (32 bytes)
//! [117]                  signer_type (u8)
//! [118..182]             signature (64 bytes)
//! [182..186]             file_name_len (u32 LE)
//! [186..186+fn_len]      file_name (UTF-8)
//! [..]+4                 bao_outboard_len (u32 LE)
//! [..]+bao_len           bao_outboard (bytes)
//! ```
//!
//! Total size depends on file_name + bao_outboard. The pipeline enforces
//! `EVENT_MAX_BLOB_BYTES` (1 MiB) at the substrate boundary.

use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_FILE};

/// Minimum wire size: the fixed prefix before the variable tail.
pub const FILE_FIXED_PREFIX_BYTES: usize = 1 + 8 + 32 + 32 + 8 + 4 + 32 + 1 + 64 + 4 + 4;
// 190

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvent {
    pub created_at_ms: u64,
    /// Canonical workspace_id this file belongs to.
    pub workspace_id: [u8; 32],
    /// Bao root hash over the file's plaintext bytes.
    pub content_hash: [u8; 32],
    /// Total plaintext size in bytes.
    pub size_bytes: u64,
    /// Number of slices that make up this file.
    pub slice_count: u32,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
    pub file_name: String,
    /// Bao outboard tree bytes for the file plaintext. Used at save-time
    /// to verify the assembled file via `bao_verify::verify_slice`.
    pub bao_outboard: Vec<u8>,
}

/// Stable field-name list used by registry meta (deps + label gates).
/// File events have no event-graph deps beyond the signer, so this stays
/// minimal. The `signed_by` field is a dep ref to a peer_shared event.
pub const FILE_FIELDS: &[&str] = &["workspace_id", "signed_by"];

impl super::super::Describe for FileEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("file_name", self.file_name.clone()),
            (
                "size",
                format!("{} bytes, {} slices", self.size_bytes, self.slice_count),
            ),
        ]
    }
}

pub fn parse_file(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < FILE_FIXED_PREFIX_BYTES {
        return Err(EventError::TooShort {
            expected: FILE_FIXED_PREFIX_BYTES,
            actual: blob.len(),
        });
    }
    let type_code = blob[0];
    if type_code != EVENT_TYPE_FILE {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_FILE,
            actual: type_code,
        });
    }
    let mut off = 1usize;

    let created_at_ms = u64::from_le_bytes(blob[off..off + 8].try_into().unwrap());
    off += 8;

    let mut workspace_id = [0u8; 32];
    workspace_id.copy_from_slice(&blob[off..off + 32]);
    off += 32;

    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&blob[off..off + 32]);
    off += 32;

    let size_bytes = u64::from_le_bytes(blob[off..off + 8].try_into().unwrap());
    off += 8;

    let slice_count = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
    off += 4;

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off..off + 32]);
    off += 32;

    let signer_type = blob[off];
    off += 1;

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off..off + 64]);
    off += 64;

    let file_name_len = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap()) as usize;
    off += 4;

    if off + file_name_len + 4 > blob.len() {
        return Err(EventError::TooShort {
            expected: off + file_name_len + 4,
            actual: blob.len(),
        });
    }
    let file_name = std::str::from_utf8(&blob[off..off + file_name_len])
        .map_err(|_| EventError::InvalidMetadata("file_name not valid UTF-8"))?
        .to_string();
    off += file_name_len;

    let bao_outboard_len = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap()) as usize;
    off += 4;

    if off + bao_outboard_len != blob.len() {
        return Err(EventError::TrailingData {
            expected: off + bao_outboard_len,
            actual: blob.len(),
        });
    }
    let bao_outboard = blob[off..off + bao_outboard_len].to_vec();

    Ok(ParsedEvent::File(FileEvent {
        created_at_ms,
        workspace_id,
        content_hash,
        size_bytes,
        slice_count,
        signed_by,
        signer_type,
        signature,
        file_name,
        bao_outboard,
    }))
}

pub fn encode_file(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let f = match event {
        ParsedEvent::File(f) => f,
        _ => return Err(EventError::WrongVariant),
    };

    let file_name_bytes = f.file_name.as_bytes();
    let total_size =
        FILE_FIXED_PREFIX_BYTES + file_name_bytes.len() + f.bao_outboard.len();
    if total_size > super::super::EVENT_MAX_BLOB_BYTES {
        return Err(EventError::ContentTooLong(total_size));
    }
    let mut out = Vec::with_capacity(total_size);
    out.push(EVENT_TYPE_FILE);
    out.extend_from_slice(&f.created_at_ms.to_le_bytes());
    out.extend_from_slice(&f.workspace_id);
    out.extend_from_slice(&f.content_hash);
    out.extend_from_slice(&f.size_bytes.to_le_bytes());
    out.extend_from_slice(&f.slice_count.to_le_bytes());
    out.extend_from_slice(&f.signed_by);
    out.push(f.signer_type);
    out.extend_from_slice(&f.signature);
    out.extend_from_slice(&(file_name_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(file_name_bytes);
    out.extend_from_slice(&(f.bao_outboard.len() as u32).to_le_bytes());
    out.extend_from_slice(&f.bao_outboard);
    Ok(out)
}

pub static FILE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_FILE,
    type_name: "file",
    projection_table: "files",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_file,
    encode: encode_file,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_codec_roundtrip() {
        let f = FileEvent {
            created_at_ms: 12345,
            workspace_id: [0x11; 32],
            content_hash: [0x22; 32],
            size_bytes: 4096,
            slice_count: 4,
            signed_by: [0x33; 32],
            signer_type: 5,
            signature: [0x44; 64],
            file_name: "test.bin".to_string(),
            bao_outboard: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        let blob = encode_file(&ParsedEvent::File(f.clone())).unwrap();
        let parsed = parse_file(&blob).unwrap();
        match parsed {
            ParsedEvent::File(decoded) => assert_eq!(decoded, f),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_file_codec_empty_outboard() {
        let f = FileEvent {
            created_at_ms: 0,
            workspace_id: [0; 32],
            content_hash: [0; 32],
            size_bytes: 0,
            slice_count: 0,
            signed_by: [0; 32],
            signer_type: 0,
            signature: [0; 64],
            file_name: String::new(),
            bao_outboard: vec![],
        };
        let blob = encode_file(&ParsedEvent::File(f.clone())).unwrap();
        let parsed = parse_file(&blob).unwrap();
        match parsed {
            ParsedEvent::File(decoded) => assert_eq!(decoded, f),
            _ => panic!("wrong variant"),
        }
    }
}
