pub mod authoring;
pub mod cli;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod retention;
pub mod rows;

pub const TYPE_SEALED_MESSAGE: u8 = layout::TYPE_SEALED_MESSAGE;
pub const TYPE_MESSAGE_DELETION: u8 = layout::TYPE_MESSAGE_DELETION;
pub const TYPE_SIGNER_PUBKEY: u8 = layout::TYPE_SIGNER_PUBKEY;
pub const TYPE_SECRET_NODE: u8 = layout::TYPE_SECRET_NODE;

pub fn expiration_timeline() -> crate::core::projection::Timeline {
    crate::core::projection::Timeline::new("sealed_message_expiry")
        .expect("valid sealed-message expiry timeline")
}

pub enum ProjectionPayload {
    Message(fact::SealedMessageFact),
    SignedMessage(
        crate::protocol::facts::identity::signed_fact::SignedPayload<fact::SealedMessageFact>,
    ),
    SignerPubkey(fact::SignerPubkeyFact),
    SecretNode(fact::SecretNodeFact),
    MessageDeletion(fact::MessageDeletionFact),
}

pub fn decode_sealed_message_payload(bytes: &[u8]) -> Result<fact::SealedMessageFact, String> {
    layout::decode_sealed_message(bytes)
}

pub fn decode_message_deletion_payload(bytes: &[u8]) -> Result<fact::MessageDeletionFact, String> {
    layout::decode_message_deletion(bytes)
}

pub fn decode_signer_pubkey_payload(bytes: &[u8]) -> Result<fact::SignerPubkeyFact, String> {
    layout::decode_signer_pubkey(bytes)
}

pub fn decode_secret_node_payload(bytes: &[u8]) -> Result<fact::SecretNodeFact, String> {
    layout::decode_secret_node(bytes)
}

pub(crate) struct Codec;

impl crate::core::projection::FactCodec for Codec {
    type Payload = ProjectionPayload;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        match fact.bytes.first().copied() {
            Some(TYPE_SEALED_MESSAGE) => {
                decode_sealed_message_payload(fact.body()).map(ProjectionPayload::Message)
            }
            Some(crate::protocol::facts::identity::signed_fact::TYPE_SIGNED_FACT) => {
                crate::protocol::facts::identity::signed_fact::decode_signed_fact_payload(
                    fact,
                    layout::TYPE_SEALED_MESSAGE,
                    "sealed message",
                    decode_sealed_message_payload,
                )
                .map(ProjectionPayload::SignedMessage)
            }
            Some(TYPE_SIGNER_PUBKEY) => {
                decode_signer_pubkey_payload(fact.body()).map(ProjectionPayload::SignerPubkey)
            }
            Some(TYPE_SECRET_NODE) => {
                decode_secret_node_payload(fact.body()).map(ProjectionPayload::SecretNode)
            }
            Some(TYPE_MESSAGE_DELETION) => {
                decode_message_deletion_payload(fact.body()).map(ProjectionPayload::MessageDeletion)
            }
            _ => Err("unknown sealed-message fact type".to_string()),
        }
    }
}
