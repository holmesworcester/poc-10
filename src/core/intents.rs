//! Intent types for atomic and deferred work.

use crate::core::store::{TableName, TableRow};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IntentKind(String);

impl IntentKind {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("intent kind cannot be empty".to_string());
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!("invalid intent kind {value:?}"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentExecution {
    Atomic,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub kind: IntentKind,
    pub execution: IntentExecution,
    pub key: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Intent {
    pub fn new(
        kind: IntentKind,
        execution: IntentExecution,
        key: impl Into<Vec<u8>>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            kind,
            execution,
            key: key.into(),
            payload: payload.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDelete {
    pub table: TableName,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicIntent {
    PutRow(TableRow),
    DeleteRow(TableDelete),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_kind_uses_registry_safe_vocabulary() {
        assert!(IntentKind::new("put_row").is_ok());
        assert!(IntentKind::new("PutRow").is_err());
    }

    #[test]
    fn intent_carries_idempotence_key() {
        let intent = Intent::new(
            IntentKind::new("materialize").unwrap(),
            IntentExecution::Deferred,
            b"same-work",
            b"payload",
        );
        assert_eq!(intent.key, b"same-work");
    }
}
