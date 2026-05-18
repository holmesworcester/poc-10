pub mod cli;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_ENDPOINT_SHARED: u8 = layout::TYPE_ENDPOINT_SHARED;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::EndpointSharedFact, String> {
    layout::decode_fact(bytes)
}
