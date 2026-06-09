use crate::core::wire::FixedSlot;

pub const HEADER_BYTES: usize = 64;
pub const CIPHERTEXT_BYTES: usize = 1024;

pub type PayloadHeader = FixedSlot<HEADER_BYTES>;
pub type PayloadCiphertext = FixedSlot<CIPHERTEXT_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPayloadFact {
    pub format: u32,
    pub algorithm: u32,
    pub header: PayloadHeader,
    pub ciphertext: PayloadCiphertext,
}

pub fn validate_payload(payload: &SealedPayloadFact) -> Result<(), String> {
    if payload.format == 0 {
        return Err("sealed payload format cannot be zero".to_string());
    }
    if payload.algorithm == 0 {
        return Err("sealed payload algorithm cannot be zero".to_string());
    }
    if payload.ciphertext.is_empty() {
        return Err("sealed payload ciphertext cannot be empty".to_string());
    }
    Ok(())
}
