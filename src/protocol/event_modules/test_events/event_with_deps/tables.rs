use crate::core::store::{Schema, TableName};

pub const STAGED_EVENTS_WITH_DEPS: TableName = TableName::new("test_events.staged_event_with_deps");

pub const SCHEMAS: &[Schema] = &[Schema::durable(
    "test_events.staged_event_with_deps.v1",
    r#"
    CREATE TABLE IF NOT EXISTS "test_events.staged_event_with_deps" (
        row_key BLOB PRIMARY KEY NOT NULL,
        row_value BLOB NOT NULL
    );
    "#,
)];
