//! Context needs and offers used to wake projection.

use crate::core::facts::{FactId, FactScope};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Role(String);

impl Role {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("context role cannot be empty".to_string());
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!("invalid context role {value:?}"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Selector(Vec<u8>);

impl Selector {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextNeed {
    pub owner: FactId,
    pub role: Role,
    pub scope: FactScope,
    pub selector: Selector,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextOffer {
    pub owner: FactId,
    pub role: Role,
    pub scope: FactScope,
    pub selector: Selector,
    pub payload_ref: FactId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextSet {
    pub needs: Vec<ContextNeed>,
    pub offers: Vec<ContextOffer>,
}

impl ContextSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn need(mut self, need: ContextNeed) -> Self {
        self.needs.push(need);
        self
    }

    pub fn offer(mut self, offer: ContextOffer) -> Self {
        self.offers.push(offer);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::FactScope;

    #[test]
    fn role_rejects_broad_free_text() {
        assert!(Role::new("exact_event").is_ok());
        assert!(Role::new("ExactEvent").is_err());
        assert!(Role::new("exact-event").is_err());
    }

    #[test]
    fn context_set_builder_keeps_needs_and_offers_explicit() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let selector = Selector::from_bytes([2; 32]);
        let set = ContextSet::new()
            .need(ContextNeed {
                owner: id,
                role: role.clone(),
                scope: FactScope::Global,
                selector: selector.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                selector,
                payload_ref: id,
            });

        assert_eq!(set.needs.len(), 1);
        assert_eq!(set.offers.len(), 1);
    }
}
