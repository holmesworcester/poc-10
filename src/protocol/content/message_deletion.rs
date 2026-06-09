//! Content message deletion fact family.
//!
//! Message deletions are signature-evidenced tombstones for message ids. Projection waits
//! for target-message and author context, records a tombstone row, and
//! publishes generic `fact_purged` context for the target message coordinate.
//! Message, reaction, file, and slice projectors keep matching needs and delete
//! their own rows plus their own fact bytes when this context arrives.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod commands;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

pub(crate) use decode::Codec;

pub const TYPE_CONTENT_MESSAGE_DELETION: u8 = encode::TYPE_CONTENT_MESSAGE_DELETION;
pub const ROOT_FAMILY_CONTENT_MESSAGE_DELETION: u32 = 2;
pub const ROOT_VERSION_CONTENT_MESSAGE_DELETION: u32 = 1;

pub const MESSAGE_DELETION_ROWS: crate::core::store::TableName =
    crate::protocol::registry::read_models::MESSAGE_DELETION_ROWS;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentMessageDeletionFact, String> {
    decode::decode_fact(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionView {
    pub workspace_id: crate::core::facts::FactId,
    pub target_message_id: crate::core::facts::FactId,
    pub target_frontier_id: Option<crate::core::facts::FactId>,
    pub target_minute: Option<u64>,
    pub author_user_id: crate::core::facts::FactId,
}

pub fn decode_any_fact(fact: &crate::core::facts::Fact) -> Result<MessageDeletionView, String> {
    if let Ok(deletion) = decode::decode_fact(fact.body()) {
        return semantic_message_deletion(deletion);
    }

    let root = crate::protocol::root::decode_fact_payload(fact.body())?;
    if root.family != ROOT_FAMILY_CONTENT_MESSAGE_DELETION {
        return Err("root is not a content message deletion".to_string());
    }
    if root.version != ROOT_VERSION_CONTENT_MESSAGE_DELETION {
        return Err("unsupported content message deletion root version".to_string());
    }
    let required = |role, label| {
        root.ref_by_role_index(role, 0)
            .map(|edge| edge.target_fact_id)
            .ok_or_else(|| format!("content message deletion root missing {label} ref"))
    };
    Ok(MessageDeletionView {
        workspace_id: required(crate::protocol::root::roles::WORKSPACE, "workspace")?,
        target_message_id: required(crate::protocol::root::roles::TARGET, "target")?,
        target_frontier_id: None,
        target_minute: None,
        author_user_id: required(crate::protocol::root::roles::AUTHOR, "author")?,
    })
}

fn semantic_message_deletion(
    deletion: fact::ContentMessageDeletionFact,
) -> Result<MessageDeletionView, String> {
    Ok(MessageDeletionView {
        workspace_id: deletion.workspace_id,
        target_message_id: deletion.target_message_id,
        target_frontier_id: Some(deletion.target_frontier_id),
        target_minute: Some(deletion.target_minute),
        author_user_id: deletion.author_user_id,
    })
}
