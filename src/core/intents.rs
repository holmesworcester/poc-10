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
        let mut reader = IntentReader::new(&intent.payload);
        reader.expect_u8(1)?;
        let op = reader.take_u8()?;
        let table_name = reader.take_sized_u16()?;
        let table = allowed_tables
            .iter()
            .copied()
            .find(|table| table.as_str().as_bytes() == table_name)
            .ok_or_else(|| "row intent table is not registered".to_string())?;
        let key = reader.take_sized_u32()?.to_vec();
        let value = reader.take_sized_u32()?.to_vec();
        reader.finish()?;

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
    let mut out = Vec::new();
    out.push(1);
    out.push(op);
    put_sized_u16(&mut out, table.as_str().as_bytes());
    put_sized_u32(&mut out, row_key);
    put_sized_u32(&mut out, row_value);
    out
}

fn put_sized_u16(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("row intent table name fits u16");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn put_sized_u32(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("row intent bytes fit u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

struct IntentReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> IntentReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_u8(&mut self, expected: u8) -> Result<(), String> {
        let actual = self.take_u8()?;
        if actual == expected {
            Ok(())
        } else {
            Err(format!("expected row intent byte {expected}, got {actual}"))
        }
    }

    fn take_u8(&mut self) -> Result<u8, String> {
        let bytes = self.take_exact(1)?;
        Ok(bytes[0])
    }

    fn take_sized_u16(&mut self) -> Result<&'a [u8], String> {
        let len = self.take_u16()? as usize;
        self.take_exact(len)
    }

    fn take_sized_u32(&mut self) -> Result<&'a [u8], String> {
        let len = self.take_u32()? as usize;
        self.take_exact(len)
    }

    fn take_u16(&mut self) -> Result<u16, String> {
        let bytes = self.take_exact(2)?;
        Ok(u16::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn take_u32(&mut self) -> Result<u32, String> {
        let bytes = self.take_exact(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn take_exact(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "row intent length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated row intent".to_string());
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err("row intent has trailing bytes".to_string())
        }
    }
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
