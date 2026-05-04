pub mod cli;
pub mod event_modules;
pub mod wire;

use std::path::Path;

use crate::core::{
    network_queues,
    store::{Schema, Store},
};
use event_modules::types::EventRecord;
use event_modules::worker::{EventRegistry, EventWithContext, ProjectionOutput};
use event_modules::Modules;

#[derive(Debug, Clone, Copy, Default)]
pub struct Protocol {
    modules: Modules,
}

impl Protocol {
    pub fn new() -> Self {
        Self {
            modules: Modules::new(),
        }
    }

    pub fn modules(&self) -> &Modules {
        &self.modules
    }

    pub fn open_store(path: impl AsRef<Path>) -> rusqlite::Result<Store> {
        Store::open_disk_with_schemas(path, &schemas())
    }

    pub fn open_memory_store() -> rusqlite::Result<Store> {
        Store::open_memory_with_schemas(&schemas())
    }
}

pub fn schemas() -> Vec<Schema> {
    let mut schemas = event_modules::schemas();
    schemas.extend_from_slice(network_queues::SCHEMAS);
    schemas
}

impl EventRegistry for Protocol {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.modules.record_from_bytes(bytes)
    }

    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        self.modules.project_record(store, event)
    }
}
