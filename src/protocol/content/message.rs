//! Content message fact family.
//!
//! Messages are the primary user-visible content records. This module owns the
//! stable message layout, authoring constructors (`create`), authority checks
//! for signed payloads, projection into opened-message/tombstone rows,
//! retention scheduling, queries, and CLI formatting. Authority and retention
//! machinery live in `project`; other content facts depend on message context
//! rather than duplicating message authority rules.

pub mod cli;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_CONTENT_MESSAGE: u8 = layout::TYPE_CONTENT_MESSAGE;
pub const COVER_HORIZON_MINUTES: u64 = 30 * 24 * 60;

const RETENTION_FLOOR_ROLE: &str = "content_retention_floor";

pub fn expiration_timeline() -> crate::core::projectors::Timeline {
    crate::core::projectors::Timeline::new("content_message_expiry")
        .expect("valid content-message expiry timeline")
}

pub fn retention_floor_need(
    owner: crate::core::facts::FactId,
    workspace_id: crate::core::facts::FactId,
) -> crate::core::context::ContextNeed {
    let key = workspace_id.to_vec();
    crate::core::context::ContextNeed::range(
        owner,
        crate::core::context::Role::expect(RETENTION_FLOOR_ROLE),
        crate::protocol::auth::workspace::scope(workspace_id),
        key.clone(),
        key,
    )
}

pub fn retention_floor_offer(
    owner: crate::core::facts::FactId,
    workspace_id: crate::core::facts::FactId,
) -> crate::core::context::ContextOffer {
    let key = workspace_id.to_vec();
    crate::core::context::ContextOffer::range(
        owner,
        crate::core::context::Role::expect(RETENTION_FLOOR_ROLE),
        crate::protocol::auth::workspace::scope(workspace_id),
        key.clone(),
        key,
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentMessageFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload =
        crate::protocol::content::message::project::DecodedFact<fact::ContentMessageFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        project::decode_signed_fact(
            fact,
            layout::TYPE_CONTENT_MESSAGE,
            "content message",
            decode_fact_payload,
        )
    }
}
