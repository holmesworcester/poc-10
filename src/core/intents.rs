//! Intent types for atomic, deferred, and ephemeral work.

use crate::core::store::{TableName, TableRow};
use crate::core::wire::{Reader, WireError, Writer};

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
    Ephemeral,
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

impl AtomicIntent {
    pub fn into_intent(self) -> Intent {
        match self {
            Self::PutRow(row) => {
                let key = row_intent_key(row.table, &row.key);
                let payload = row_intent_payload(0, row.table, &row.key, &row.value);
                Intent::new(
                    IntentKind::new("put_row").unwrap(),
                    IntentExecution::Atomic,
                    key,
                    payload,
                )
            }
            Self::DeleteRow(delete) => delete.into_intent(),
        }
    }

    pub fn from_intent(intent: &Intent, allowed_tables: &[TableName]) -> Result<Self, String> {
        if intent.execution != IntentExecution::Atomic {
            return Err("row intent must be atomic".to_string());
        }
        let mut reader = Reader::new(&intent.payload);
        reader.expect_u8(1).map_err(row_intent_error)?;
        let op = reader.u8().map_err(row_intent_error)?;
        let table_name = reader.bytes_u16be().map_err(row_intent_error)?;
        let table = allowed_tables
            .iter()
            .copied()
            .find(|table| table.as_str().as_bytes() == table_name)
            .ok_or_else(|| "row intent table is not registered".to_string())?;
        let key = reader.bytes_u32be().map_err(row_intent_error)?.to_vec();
        let value = reader.bytes_u32be().map_err(row_intent_error)?.to_vec();
        reader.finish().map_err(row_intent_error)?;

        if intent.key != row_intent_key(table, &key) {
            return Err("row intent idempotence key does not match payload".to_string());
        }

        match (intent.kind.as_str(), op) {
            ("put_row", 0) => Ok(Self::PutRow(TableRow { table, key, value })),
            ("delete_row", 1) if value.is_empty() => {
                Ok(Self::DeleteRow(TableDelete { table, key }))
            }
            ("delete_row", 1) => Err("delete row intent must not carry a value".to_string()),
            _ => Err("row intent kind and payload op do not match".to_string()),
        }
    }
}

impl TableDelete {
    pub fn into_intent(self) -> Intent {
        let key = row_intent_key(self.table, &self.key);
        let payload = row_intent_payload(1, self.table, &self.key, &[]);
        Intent::new(
            IntentKind::new("delete_row").unwrap(),
            IntentExecution::Atomic,
            key,
            payload,
        )
    }
}

fn row_intent_key(table: TableName, row_key: &[u8]) -> Vec<u8> {
    let mut key = table.as_str().as_bytes().to_vec();
    key.push(0);
    key.extend_from_slice(row_key);
    key
}

fn row_intent_payload(op: u8, table: TableName, row_key: &[u8], row_value: &[u8]) -> Vec<u8> {
    let mut out = Writer::new();
    out.u8(1);
    out.u8(op);
    out.bytes_u16be(table.as_str().as_bytes())
        .expect("row intent table name fits u16");
    out.bytes_u32be(row_key).expect("row intent key fits u32");
    out.bytes_u32be(row_value)
        .expect("row intent value fits u32");
    out.finish()
}

fn row_intent_error(err: WireError) -> String {
    format!("invalid row intent payload: {err}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TABLE: TableName = TableName::new("test.rows");

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

    #[test]
    fn put_row_intent_is_keyed_by_table_and_row_key_not_value() {
        let row_a = TableRow {
            table: TEST_TABLE,
            key: b"row-key".to_vec(),
            value: b"value-a".to_vec(),
        };
        let row_b = TableRow {
            table: TEST_TABLE,
            key: b"row-key".to_vec(),
            value: b"value-b".to_vec(),
        };

        let intent_a = AtomicIntent::PutRow(row_a).into_intent();
        let intent_b = AtomicIntent::PutRow(row_b).into_intent();

        assert_eq!(intent_a.kind.as_str(), "put_row");
        assert_eq!(intent_a.execution, IntentExecution::Atomic);
        assert_eq!(intent_a.key, intent_b.key);
        assert_ne!(intent_a.payload, intent_b.payload);
        assert!(intent_a.key.starts_with(b"test.rows\0row-key"));
    }

    #[test]
    fn delete_row_intent_shares_table_row_key_with_put_row() {
        let put = AtomicIntent::PutRow(TableRow {
            table: TEST_TABLE,
            key: b"row-key".to_vec(),
            value: b"value".to_vec(),
        })
        .into_intent();
        let delete = TableDelete {
            table: TEST_TABLE,
            key: b"row-key".to_vec(),
        }
        .into_intent();

        assert_eq!(delete.kind.as_str(), "delete_row");
        assert_eq!(delete.execution, IntentExecution::Atomic);
        assert_eq!(delete.key, put.key);
        assert_ne!(delete.payload, put.payload);
    }

    #[test]
    fn atomic_row_intents_round_trip_through_registered_tables() {
        let row = TableRow {
            table: TEST_TABLE,
            key: b"row-key".to_vec(),
            value: b"value".to_vec(),
        };
        let delete = TableDelete {
            table: TEST_TABLE,
            key: b"row-key".to_vec(),
        };

        let decoded_put = AtomicIntent::from_intent(
            &AtomicIntent::PutRow(row.clone()).into_intent(),
            &[TEST_TABLE],
        )
        .expect("decode put");
        let decoded_delete =
            AtomicIntent::from_intent(&delete.clone().into_intent(), &[TEST_TABLE])
                .expect("decode delete");

        assert_eq!(decoded_put, AtomicIntent::PutRow(row));
        assert_eq!(decoded_delete, AtomicIntent::DeleteRow(delete));
    }

    #[test]
    fn atomic_row_intent_decode_rejects_unregistered_table() {
        let intent = AtomicIntent::PutRow(TableRow {
            table: TEST_TABLE,
            key: b"row-key".to_vec(),
            value: b"value".to_vec(),
        })
        .into_intent();

        let err = AtomicIntent::from_intent(&intent, &[]).expect_err("unregistered table");

        assert!(err.contains("table is not registered"), "{err}");
    }

    #[test]
    fn atomic_row_intent_decode_rejects_key_payload_mismatch() {
        let mut intent = AtomicIntent::PutRow(TableRow {
            table: TEST_TABLE,
            key: b"row-key".to_vec(),
            value: b"value".to_vec(),
        })
        .into_intent();
        intent.key.push(b'!');

        let err = AtomicIntent::from_intent(&intent, &[TEST_TABLE]).expect_err("key mismatch");

        assert!(err.contains("key does not match payload"), "{err}");
    }
}
