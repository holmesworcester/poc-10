//! CLI parsing and formatting for content-file deletion.
//!
//! File deletion commands accept a user-facing selector, while the protocol
//! operates on fact ids and file ids. This file bridges that gap by resolving a
//! selector against the live projected file view and by rendering the deletion
//! receipt. Deletion authority and row mutation rules stay in the command and
//! projection modules.

use crate::core::cli::{decode_hex_32_named, encode_hex_32, CliOutput};
use crate::core::facts::FactId;
use crate::core::store::Store;
use crate::protocol::content::file::queries::{self, ContentFileRow};

use super::commands::DeleteFileReceipt;

pub const DELETE_FILE_USAGE: &str = "delete-file WORKSPACE_ID_HEX FILE_SELECTOR";

pub fn delete_file_output(receipt: &DeleteFileReceipt) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex_32(&receipt.workspace_id)),
        format!("fact_id: {}", encode_hex_32(&receipt.deletion_fact_id)),
        format!("target_file_id: {}", encode_hex_32(&receipt.target_file_id)),
        format!("created_at_ms: {}", receipt.created_at_ms),
    ])
}

pub fn resolve_file_selector(
    store: &Store,
    workspace_id: FactId,
    selector: &str,
) -> Result<ContentFileRow, String> {
    let files = queries::content_file_rows(store, workspace_id)?;
    if let Some(index) = selector.strip_prefix('#') {
        let index = index
            .parse::<usize>()
            .map_err(|_| "file selector index must be a positive integer".to_string())?;
        if index == 0 {
            return Err("file selector index must be a positive integer".to_string());
        }
        return files
            .get(index - 1)
            .cloned()
            .ok_or_else(|| "file selector does not match a file".to_string());
    }

    let file_id = decode_hex_32_named(selector, "file id")?;
    files
        .into_iter()
        .find(|file| file.file_fact_id == file_id || file.file_id == file_id)
        .ok_or_else(|| "file selector does not match a file".to_string())
}
