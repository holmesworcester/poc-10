//! Checked SQL wake plans for queue fanout.
//!
//! A wake plan is a read-only SELECT over declared tables. Pipeline workers
//! choose the destination queue table and columns; the plan only describes the
//! bounded source rows and bound parameters.

use crate::core::store::{ColumnValue, Store, TableName};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakePlan {
    pub sql: &'static str,
    pub allowed_tables: &'static [TableName],
    pub params: Vec<WakeParam>,
}

impl WakePlan {
    pub fn new(
        sql: &'static str,
        allowed_tables: &'static [TableName],
        params: Vec<WakeParam>,
    ) -> Self {
        Self {
            sql,
            allowed_tables,
            params,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeParam {
    pub name: &'static str,
    pub value: WakeValue,
}

impl WakeParam {
    pub fn bytes(name: &'static str, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name,
            value: WakeValue::Bytes(value.into()),
        }
    }

    pub fn text(name: &'static str, value: impl Into<String>) -> Self {
        Self {
            name,
            value: WakeValue::Text(value.into()),
        }
    }

    pub fn u64(name: &'static str, value: u64) -> Self {
        Self {
            name,
            value: WakeValue::U64(value),
        }
    }

    pub fn i64(name: &'static str, value: i64) -> Self {
        Self {
            name,
            value: WakeValue::I64(value),
        }
    }

    pub fn bool(name: &'static str, value: bool) -> Self {
        Self {
            name,
            value: WakeValue::Bool(value),
        }
    }

    fn as_column_value(&self) -> ColumnValue<'_> {
        self.value.as_column_value()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeValue {
    Bytes(Vec<u8>),
    Text(String),
    U64(u64),
    I64(i64),
    Bool(bool),
}

impl WakeValue {
    fn as_column_value(&self) -> ColumnValue<'_> {
        match self {
            Self::Bytes(value) => ColumnValue::Bytes(value),
            Self::Text(value) => ColumnValue::Text(value),
            Self::U64(value) => ColumnValue::U64(*value),
            Self::I64(value) => ColumnValue::I64(*value),
            Self::Bool(value) => ColumnValue::Bool(*value),
        }
    }
}

pub(crate) fn execute_wake_plan_in_tx(
    store: &Store,
    target_table: TableName,
    target_columns: &[&str],
    plan: &WakePlan,
) -> rusqlite::Result<usize> {
    let params = plan
        .params
        .iter()
        .map(|param| (param.name, param.as_column_value()))
        .collect::<Vec<_>>();
    store.insert_typed_rows_from_select_in_tx(
        target_table,
        target_columns,
        plan.sql,
        plan.allowed_tables,
        &params,
    )
}
