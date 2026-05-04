pub mod actors;
pub mod app;
pub mod event_modules;
pub mod network;

use crate::core::pipeline::EventRegistry;
use crate::core::store::{EventRecord, ProjectionOutput, Store};
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
}

impl EventRegistry for Protocol {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.modules.record_from_bytes(bytes)
    }

    fn project_record(
        &self,
        store: &Store,
        record: &EventRecord,
    ) -> Result<ProjectionOutput, String> {
        self.modules.project_record(store, record)
    }
}
