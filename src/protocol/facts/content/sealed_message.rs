pub mod authoring;
pub mod cli;
pub mod create;
pub mod fact;
pub mod intent;
pub mod layout;
pub mod project;
pub mod queries;
pub mod retention;
pub mod rows;

pub const TYPE_SEALED_MESSAGE: u8 = layout::TYPE_SEALED_MESSAGE;
pub const TYPE_MESSAGE_DELETION: u8 = layout::TYPE_MESSAGE_DELETION;

pub fn decode_sealed_message_payload(bytes: &[u8]) -> Result<fact::SealedMessageFact, String> {
    layout::decode_sealed_message(bytes)
}

pub fn decode_message_deletion_payload(bytes: &[u8]) -> Result<fact::MessageDeletionFact, String> {
    layout::decode_message_deletion(bytes)
}
