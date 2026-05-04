use crate::core::store::{Schema, TableName};

pub const STAGED_EVENTS_WITH_DEPS: TableName = TableName::new("test_events.staged_event_with_deps");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "test_events.staged_event_with_deps.v1",
    STAGED_EVENTS_WITH_DEPS,
)];
