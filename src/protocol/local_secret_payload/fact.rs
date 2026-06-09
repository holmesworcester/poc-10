use crate::core::wire::FixedSlot;

pub const SECRET_BYTES: usize = 256;
pub type LocalSecretBytes = FixedSlot<SECRET_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSecretPayloadFact {
    pub family: u32,
    pub version: u32,
    pub bytes: LocalSecretBytes,
}

pub fn validate_secret(secret: &LocalSecretPayloadFact) -> Result<(), String> {
    if secret.family == 0 {
        return Err("local secret family cannot be zero".to_string());
    }
    if secret.version == 0 {
        return Err("local secret version cannot be zero".to_string());
    }
    if secret.bytes.is_empty() {
        return Err("local secret bytes cannot be empty".to_string());
    }
    Ok(())
}
