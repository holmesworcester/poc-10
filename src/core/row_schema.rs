//! Schema-backed helpers for opaque protocol row tables.
//!
//! Protocol row declarations name their key and value fields, while core keeps
//! the generic `(table, key, value)` storage boundary. These helpers provide the
//! mechanical encode/decode layer that can replace handwritten `rows.rs` byte
//! packing one family at a time.

use crate::core::store::{TableName, TableRow};

/// Primitive field shapes supported by schema-backed opaque row codecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowFieldType {
    Bytes(usize),
    U8,
    U64Be,
}

impl RowFieldType {
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::Bytes(len) => len,
            Self::U8 => 1,
            Self::U64Be => 8,
        }
    }
}

/// One named field in a row key or value layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowField {
    pub name: &'static str,
    pub field_type: RowFieldType,
}

impl RowField {
    pub const fn bytes(name: &'static str, len: usize) -> Self {
        Self {
            name,
            field_type: RowFieldType::Bytes(len),
        }
    }

    pub const fn bytes32(name: &'static str) -> Self {
        Self::bytes(name, 32)
    }

    pub const fn u8(name: &'static str) -> Self {
        Self {
            name,
            field_type: RowFieldType::U8,
        }
    }

    pub const fn u64be(name: &'static str) -> Self {
        Self {
            name,
            field_type: RowFieldType::U64Be,
        }
    }
}

/// Runtime value for one row field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowValue {
    Bytes(Vec<u8>),
    U8(u8),
    U64(u64),
}

impl RowValue {
    /// Borrow a `Bytes` field, naming it for error messages.
    pub fn as_bytes(&self, name: &str) -> Result<&[u8], String> {
        match self {
            RowValue::Bytes(bytes) => Ok(bytes),
            _ => Err(format!("{name} must be bytes")),
        }
    }

    /// Read a fixed 32-byte `Bytes` field.
    pub fn as_bytes32(&self, name: &str) -> Result<[u8; 32], String> {
        self.as_bytes(name)?
            .try_into()
            .map_err(|_| format!("{name} must be 32 bytes"))
    }

    /// Read a `U64` field.
    pub fn as_u64(&self, name: &str) -> Result<u64, String> {
        match self {
            RowValue::U64(value) => Ok(*value),
            _ => Err(format!("{name} must be u64")),
        }
    }

    /// Read a `U8` field.
    pub fn as_u8(&self, name: &str) -> Result<u8, String> {
        match self {
            RowValue::U8(value) => Ok(*value),
            _ => Err(format!("{name} must be u8")),
        }
    }
}

/// Schema for one opaque row table's key/value bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowTableSchema {
    pub table: TableName,
    pub key_fields: &'static [RowField],
    pub value_fields: &'static [RowField],
}

impl RowTableSchema {
    pub const fn new(
        table: TableName,
        key_fields: &'static [RowField],
        value_fields: &'static [RowField],
    ) -> Self {
        Self {
            table,
            key_fields,
            value_fields,
        }
    }

    pub fn key_len(&self) -> usize {
        encoded_len(self.key_fields)
    }

    pub fn value_len(&self) -> usize {
        encoded_len(self.value_fields)
    }

    pub fn encode_key(&self, values: &[RowValue]) -> Result<Vec<u8>, String> {
        encode_fields("row key", self.key_fields, values)
    }

    pub fn encode_value(&self, values: &[RowValue]) -> Result<Vec<u8>, String> {
        encode_fields("row value", self.value_fields, values)
    }

    pub fn decode_key(&self, bytes: &[u8]) -> Result<Vec<RowValue>, String> {
        decode_fields("row key", self.key_fields, bytes)
    }

    pub fn decode_value(&self, bytes: &[u8]) -> Result<Vec<RowValue>, String> {
        decode_fields("row value", self.value_fields, bytes)
    }

    pub fn key_prefix(&self, values: &[RowValue]) -> Result<Vec<u8>, String> {
        if values.len() > self.key_fields.len() {
            return Err(format!(
                "row key prefix has {} fields, expected at most {}",
                values.len(),
                self.key_fields.len()
            ));
        }
        encode_fields("row key prefix", &self.key_fields[..values.len()], values)
    }

    pub fn row(&self, key: &[RowValue], value: &[RowValue]) -> Result<TableRow, String> {
        Ok(TableRow {
            table: self.table,
            key: self.encode_key(key)?,
            value: self.encode_value(value)?,
        })
    }
}

fn encoded_len(fields: &[RowField]) -> usize {
    fields
        .iter()
        .map(|field| field.field_type.encoded_len())
        .sum()
}

fn encode_fields(label: &str, fields: &[RowField], values: &[RowValue]) -> Result<Vec<u8>, String> {
    if fields.len() != values.len() {
        return Err(format!(
            "{label} has {} fields, expected {}",
            values.len(),
            fields.len()
        ));
    }
    let mut out = Vec::with_capacity(encoded_len(fields));
    for (field, value) in fields.iter().zip(values) {
        encode_field(label, field, value, &mut out)?;
    }
    Ok(out)
}

fn encode_field(
    label: &str,
    field: &RowField,
    value: &RowValue,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    match (field.field_type, value) {
        (RowFieldType::Bytes(expected), RowValue::Bytes(bytes)) => {
            if bytes.len() != expected {
                return Err(format!(
                    "{label} field {} has {} bytes, expected {expected}",
                    field.name,
                    bytes.len()
                ));
            }
            out.extend_from_slice(bytes);
        }
        (RowFieldType::U8, RowValue::U8(value)) => out.push(*value),
        (RowFieldType::U64Be, RowValue::U64(value)) => out.extend_from_slice(&value.to_be_bytes()),
        _ => {
            return Err(format!(
                "{label} field {} value does not match {:?}",
                field.name, field.field_type
            ));
        }
    }
    Ok(())
}

fn decode_fields(label: &str, fields: &[RowField], bytes: &[u8]) -> Result<Vec<RowValue>, String> {
    let expected = encoded_len(fields);
    if bytes.len() != expected {
        return Err(format!(
            "{label} has {} bytes, expected {expected}",
            bytes.len()
        ));
    }
    let mut offset = 0;
    let mut values = Vec::with_capacity(fields.len());
    for field in fields {
        values.push(decode_field(field, bytes, &mut offset));
    }
    Ok(values)
}

fn decode_field(field: &RowField, bytes: &[u8], offset: &mut usize) -> RowValue {
    match field.field_type {
        RowFieldType::Bytes(len) => {
            let value = bytes[*offset..*offset + len].to_vec();
            *offset += len;
            RowValue::Bytes(value)
        }
        RowFieldType::U8 => {
            let value = bytes[*offset];
            *offset += 1;
            RowValue::U8(value)
        }
        RowFieldType::U64Be => {
            let mut value = [0; 8];
            value.copy_from_slice(&bytes[*offset..*offset + 8]);
            *offset += 8;
            RowValue::U64(u64::from_be_bytes(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TABLE: TableName = TableName::new("test_schema_rows");
    const KEY_FIELDS: &[RowField] = &[RowField::bytes32("workspace_id"), RowField::u8("bucket")];
    const VALUE_FIELDS: &[RowField] = &[
        RowField::u64be("created_at_ms"),
        RowField::bytes("payload", 3),
    ];
    const TEST_SCHEMA: RowTableSchema = RowTableSchema::new(TEST_TABLE, KEY_FIELDS, VALUE_FIELDS);

    #[test]
    fn schema_encodes_and_decodes_named_key_and_value_fields() {
        let key = vec![RowValue::Bytes(vec![1; 32]), RowValue::U8(7)];
        let value = vec![RowValue::U64(42), RowValue::Bytes(vec![9, 8, 7])];

        let row = TEST_SCHEMA.row(&key, &value).expect("row");

        assert_eq!(row.table, TEST_TABLE);
        assert_eq!(row.key.len(), TEST_SCHEMA.key_len());
        assert_eq!(row.value.len(), TEST_SCHEMA.value_len());
        assert_eq!(TEST_SCHEMA.decode_key(&row.key).expect("key"), key);
        assert_eq!(TEST_SCHEMA.decode_value(&row.value).expect("value"), value);
    }

    #[test]
    fn schema_rejects_wrong_length_values() {
        let value = vec![RowValue::U64(42), RowValue::Bytes(vec![9, 8])];
        let error = TEST_SCHEMA
            .encode_value(&value)
            .expect_err("short payload should fail");
        assert!(error.contains("payload has 2 bytes, expected 3"));

        let error = TEST_SCHEMA
            .decode_value(&[0; 3])
            .expect_err("short value should fail");
        assert!(error.contains("row value has 3 bytes, expected 11"));
    }

    #[test]
    fn schema_builds_key_prefixes_from_leading_key_fields() {
        let prefix = TEST_SCHEMA
            .key_prefix(&[RowValue::Bytes(vec![1; 32])])
            .expect("prefix");
        assert_eq!(prefix, vec![1; 32]);
    }
}
