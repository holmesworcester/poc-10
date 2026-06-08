//! Content message deletion fact family.
//!
//! Message deletions are signed tombstones for message ids. Projection waits
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

pub const MESSAGE_DELETION_ROWS: crate::core::store::TableName =
    crate::protocol::registry::read_models::MESSAGE_DELETION_ROWS;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentMessageDeletionFact, String> {
    decode::decode_fact(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionView {
    pub workspace_id: crate::core::facts::FactId,
    pub target_message_id: crate::core::facts::FactId,
    pub target_frontier_id: crate::core::facts::FactId,
    pub target_minute: u64,
    pub author_user_id: crate::core::facts::FactId,
}

pub fn decode_any_fact(fact: &crate::core::facts::Fact) -> Result<MessageDeletionView, String> {
    let deletion = decode::decode_fact(fact.body())?;
    semantic_message_deletion(deletion)
}

fn semantic_message_deletion(
    deletion: fact::ContentMessageDeletionFact,
) -> Result<MessageDeletionView, String> {
    Ok(MessageDeletionView {
        workspace_id: deletion.workspace_id,
        target_message_id: deletion.target_message_id,
        target_frontier_id: deletion.target_frontier_id,
        target_minute: deletion.target_minute,
        author_user_id: deletion.author_user_id,
    })
}
