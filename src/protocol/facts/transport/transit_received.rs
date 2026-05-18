pub mod addr;
pub mod fact;
pub mod layout;
pub mod project;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::TransitReceivedFact, String> {
    layout::decode_fact(bytes)
}
