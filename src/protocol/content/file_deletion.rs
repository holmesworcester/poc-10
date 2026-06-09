//! Content file deletion fact family.
//!
//! File deletions are author-signed tombstones for file ids. Commands construct
//! the deletion fact from user selection, projection verifies target and author
//! context, and projection publishes generic `fact_purged` context for the target
//! file coordinate. Keep deletion authorization here; file metadata and slice
//! projection only consume the resulting context and remove their own state.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod cli;
pub mod commands;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

pub(crate) use decode::Codec;

pub const TYPE_CONTENT_FILE_DELETION: u8 = encode::TYPE_CONTENT_FILE_DELETION;
pub const ROOT_FAMILY_CONTENT_FILE_DELETION: u32 = 3;
pub const ROOT_VERSION_CONTENT_FILE_DELETION: u32 = 1;

pub const FILE_DELETION_ROWS: crate::core::store::TableName =
    crate::protocol::registry::read_models::FILE_DELETION_ROWS;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentFileDeletionFact, String> {
    decode::decode_fact(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDeletionView {
    pub workspace_id: crate::core::facts::FactId,
    pub target_file_id: crate::core::facts::FactId,
    pub author_user_id: crate::core::facts::FactId,
}

pub fn decode_any_fact(fact: &crate::core::facts::Fact) -> Result<FileDeletionView, String> {
    if let Ok(deletion) = decode::decode_fact(fact.body()) {
        return Ok(FileDeletionView {
            workspace_id: deletion.workspace_id,
            target_file_id: deletion.target_file_id,
            author_user_id: deletion.author_user_id,
        });
    }

    let root = crate::protocol::root::decode_fact_payload(fact.body())?;
    if root.family != ROOT_FAMILY_CONTENT_FILE_DELETION {
        return Err("root is not a content file deletion".to_string());
    }
    if root.version != ROOT_VERSION_CONTENT_FILE_DELETION {
        return Err("unsupported content file deletion root version".to_string());
    }
    let required = |role, label| {
        root.ref_by_role_index(role, 0)
            .map(|edge| edge.target_fact_id)
            .ok_or_else(|| format!("content file deletion root missing {label} ref"))
    };
    Ok(FileDeletionView {
        workspace_id: required(crate::protocol::root::roles::WORKSPACE, "workspace")?,
        target_file_id: required(crate::protocol::root::roles::TARGET, "target")?,
        author_user_id: required(crate::protocol::root::roles::AUTHOR, "author")?,
    })
}
