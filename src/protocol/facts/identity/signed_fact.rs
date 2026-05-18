pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub use create::*;
pub use fact::*;

pub const TYPE_SIGNED_FACT: u8 = layout::TYPE_SIGNED_FACT;
pub const SIGNED_FACT_BYTES: usize = layout::SIGNED_FACT_BYTES;

pub fn decode_envelope(bytes: &[u8]) -> Result<fact::SignedFactEnvelope, String> {
    layout::decode_signed_fact(bytes)
}
