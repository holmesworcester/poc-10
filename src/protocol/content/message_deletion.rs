//! Content message deletion fact family.
//!
//! Message deletions are signed tombstones for message ids. Projection waits
//! for target-message and author context, records a tombstone row, and
//! publishes `content_purged` context for the target message coordinate.
//! Message, reaction, file, and slice projectors keep matching needs and delete
//! their own rows plus their own fact bytes when this context arrives.

pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_CONTENT_MESSAGE_DELETION: u8 = layout::TYPE_CONTENT_MESSAGE_DELETION;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentMessageDeletionFact, String> {
    layout::decode_fact(bytes)
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
    match fact.bytes.first().copied() {
        Some(crate::protocol::auth::signed_fact::TYPE_SIGNED_FACT) => {
            let envelope = crate::protocol::auth::signed_fact::decode_envelope(fact.body())?;
            match envelope.inner_type {
                layout::TYPE_CONTENT_MESSAGE_DELETION => {
                    semantic_message_deletion(layout::decode_fact(&envelope.payload)?)
                }
                _ => Err("signed fact does not contain a message deletion".to_string()),
            }
        }
        _ => Err("message deletion fact must be signed".to_string()),
    }
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

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload =
        crate::protocol::content::message::project::DecodedFact<fact::ContentMessageDeletionFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::content::message::project::decode_signed_fact(
            fact,
            layout::TYPE_CONTENT_MESSAGE_DELETION,
            "message deletion",
            decode_fact_payload,
        )
    }
}
