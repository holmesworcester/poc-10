//! Protocol-neutral fact id and scope types.

pub type FactId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeKind(String);

impl ScopeKind {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("scope kind cannot be empty".to_string());
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!("invalid scope kind {value:?}"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactScope {
    Global,
    Local,
    Scoped { kind: ScopeKind, id: FactId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub id: FactId,
    pub scope: FactScope,
    pub timestamp: u64,
    pub bytes: Vec<u8>,
}

impl Fact {
    pub fn new(scope: FactScope, timestamp: u64, bytes: Vec<u8>) -> Self {
        let id = fact_id(&bytes);
        Self {
            id,
            scope,
            timestamp,
            bytes,
        }
    }
}

pub fn fact_id(bytes: &[u8]) -> FactId {
    *blake3::hash(bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fact_id_is_deterministic_and_input_sensitive() {
        assert_eq!(fact_id(b"a"), fact_id(b"a"));
        assert_ne!(fact_id(b"a"), fact_id(b"b"));
    }

    #[test]
    fn scope_kind_is_small_stable_vocabulary() {
        assert!(ScopeKind::new("local_1").is_ok());
        assert!(ScopeKind::new("").is_err());
        assert!(ScopeKind::new("Bad").is_err());
        assert!(ScopeKind::new("bad-name").is_err());
    }
}
