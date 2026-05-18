pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_SYNC_HAVE_ID: u8 = layout::TYPE_SYNC_HAVE_ID;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncHaveIdFact, String> {
    layout::decode_fact(bytes)
}

pub fn advertisement_fact(
    connection_id: crate::core::facts::FactId,
    fact: &crate::core::facts::Fact,
) -> Result<crate::core::facts::Fact, String> {
    let have = fact::SyncHaveIdFact {
        connection_id,
        timestamp: fact.timestamp,
        fact_id: fact.id,
    };
    Ok(crate::core::facts::Fact::new(
        crate::core::facts::FactScope::Global,
        fact.timestamp,
        layout::encode_fact(&have)?,
    ))
}

pub(crate) struct Codec;

impl crate::core::projection::FactCodec for Codec {
    type Payload = fact::SyncHaveIdFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
