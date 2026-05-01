use std::collections::HashMap;

use rusqlite::Connection;

use super::{EventError, ParsedEvent};
use crate::projection::contract::ProjectorResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareScope {
    Shared,
    Local,
}

impl ShareScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShareScope::Shared => "shared",
            ShareScope::Local => "local",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPrivacy {
    PlaintextOnly,
    Optional,
    RequireEncrypted,
}

pub struct EventTypeMeta {
    pub type_code: u8,
    pub type_name: &'static str,
    pub projection_table: &'static str,
    pub share_scope: ShareScope,
    pub dep_fields: &'static [&'static str],
    /// Parallel to dep_fields: valid type codes for each dep.
    /// Empty slice means any type is allowed (no type check).
    pub dep_field_type_codes: &'static [&'static [u8]],
    pub signer_required: bool,
    pub signature_byte_len: usize,
    /// Whether this event type is admissible as inner payload of an encrypted wrapper.
    /// Identity events, encrypted (nested), and bench_dep_perf_testing are not permitted.
    pub encryptable: bool,
    pub parse: fn(&[u8]) -> Result<ParsedEvent, EventError>,
    pub encode: fn(&ParsedEvent) -> Result<Vec<u8>, EventError>,
    /// Module-owned pure projector function. The pipeline dispatches to this
    /// via registry lookup — no central match statement required.
    pub projector: fn(
        &str,
        &ParsedEvent,
        &crate::projection::contract::ContextSnapshot,
    ) -> ProjectorResult,
    /// Module-owned schema declaration. The runtime walks the registry on
    /// boot (`ensure_all_module_schemas`) and invokes this for every
    /// registered meta, so each event module materializes its own tables
    /// without `state/db` knowing the domain shape.
    ///
    /// `None` for purely transient events that own no projection table
    /// (e.g. `negentropy`, `sync_window`).
    pub ensure_schema: Option<fn(&Connection) -> rusqlite::Result<()>>,
}

pub struct EventRegistry {
    by_code: HashMap<u8, &'static EventTypeMeta>,
}

impl EventRegistry {
    pub fn new(metas: &[&'static EventTypeMeta]) -> Self {
        let mut by_code = HashMap::new();
        for meta in metas {
            by_code.insert(meta.type_code, *meta);
        }
        Self { by_code }
    }

    pub fn lookup(&self, type_code: u8) -> Option<&'static EventTypeMeta> {
        self.by_code.get(&type_code).copied()
    }

    pub fn lookup_by_name(&self, type_name: &str) -> Option<&'static EventTypeMeta> {
        self.by_code
            .values()
            .copied()
            .find(|meta| meta.type_name == type_name)
    }

    /// Iterate every registered meta. Order is insertion-independent
    /// (HashMap iteration); callers that depend on a specific order
    /// (e.g. dependency-respecting schema bootstrap) must not rely on
    /// it here. Schema fns are required to be idempotent and order-
    /// independent.
    pub fn iter(&self) -> impl Iterator<Item = &'static EventTypeMeta> + '_ {
        self.by_code.values().copied()
    }
}

impl EventTypeMeta {
    pub fn transport_privacy(&self) -> TransportPrivacy {
        match self.type_code {
            super::EVENT_TYPE_MESSAGE
            | super::EVENT_TYPE_REACTION
            | super::EVENT_TYPE_MESSAGE_DELETION => TransportPrivacy::RequireEncrypted,
            super::EVENT_TYPE_KEY_SECRET => TransportPrivacy::Optional,
            _ => TransportPrivacy::PlaintextOnly,
        }
    }
}
