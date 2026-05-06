//! Event-module registry and cross-domain protocol facade.
//!
//! Leaf modules own concrete event syntax and projection rules. Workers own
//! active work such as unwrap, wrap, and sync comparison. This registry is the
//! narrow place where those independent pieces are selected by tag.
//!
//! The file should read as routing, not implementation. A good addition here
//! names which module owns a behavior and forwards to it. A suspicious addition
//! starts decoding fields inline, writing rows directly, or making a network
//! decision without going through the relevant worker.

pub mod connection;
pub mod content;
pub mod identity;
pub mod schema;
pub mod sync;
pub mod test_events;
pub mod types;
pub use crate::workers::common_event_pipeline as worker;

use std::sync::Arc;

use crate::core::store::{Schema, Store};
use crate::protocol::event_modules::types::{EventRecord, ReceiveMetadata};
use crate::protocol::event_modules::worker::{
    EventRegistry, EventWithContext, ProjectionOutput, ReceivedRecord,
};
use crate::workers::schema::{TransitProvenance, TransitUnwrap};

#[derive(Debug, Clone, Default)]
pub struct Modules {
    sync_index: Arc<sync::SyncIndex>,
}

impl Modules {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn sync_index(&self) -> &sync::SyncIndex {
        &self.sync_index
    }

    pub fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        record_from_bytes(bytes)
    }

    pub fn project_record(
        &self,
        _store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        // Projection dispatch is tag-based and intentionally shallow. Each
        // branch immediately hands control to the owning domain so this registry
        // does not accumulate projector logic.
        let bytes = &event.record.canonical_bytes;
        if let Some(output) = identity::project_record(event)? {
            return Ok(output);
        }
        if connection::is_projection_record(bytes) {
            return connection::project_record(event);
        }
        if let Some(output) = sync::project_record(event)? {
            return Ok(output);
        }
        if let Some(output) = content::project_record(event)? {
            return Ok(output);
        }
        if let Some(output) = test_events::project_record(bytes)? {
            return Ok(output);
        }
        let tag = bytes.first().copied().unwrap_or_default();
        Err(format!("unknown event type {tag}"))
    }
}

pub fn schemas() -> Vec<Schema> {
    // Schema aggregation is explicit so storage ownership remains visible in
    // review. Adding a module-owned table should add one line here and the
    // actual declaration in that module's `schema.rs`.
    let mut out = Vec::new();
    out.extend_from_slice(schema::SCHEMAS);
    out.extend_from_slice(identity::admin::schema::SCHEMAS);
    out.extend_from_slice(identity::device_invite::schema::SCHEMAS);
    out.extend_from_slice(identity::endpoint::schema::SCHEMAS);
    out.extend_from_slice(identity::endpoint_shared::schema::SCHEMAS);
    out.extend_from_slice(identity::invite::schema::SCHEMAS);
    out.extend_from_slice(identity::user::schema::SCHEMAS);
    out.extend_from_slice(identity::user_invite::schema::SCHEMAS);
    out.extend_from_slice(identity::workspace::schema::SCHEMAS);
    out.extend_from_slice(content::content_event::schema::SCHEMAS);
    out.extend_from_slice(connection::schema::SCHEMAS);
    out.extend_from_slice(test_events::event_with_deps::schema::SCHEMAS);
    out
}

impl EventRegistry for Modules {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.record_from_bytes(bytes)
    }

    fn record_from_canonical_in(
        &self,
        store: &Store,
        bytes: Vec<u8>,
        receive: Option<ReceiveMetadata>,
        provenance: Option<TransitProvenance>,
    ) -> Result<ReceivedRecord, String> {
        match provenance {
            Some(provenance) => record_from_transit_canonical_in(store, bytes, provenance),
            None => {
                let record = self.record_from_bytes(bytes)?;
                Ok(match receive {
                    Some(receive) => ReceivedRecord::with_receive(record, receive),
                    None => ReceivedRecord::new(record),
                })
            }
        }
    }

    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        self.project_record(store, event)
    }
}

fn record_from_transit_canonical_in(
    store: &Store,
    bytes: Vec<u8>,
    provenance: TransitProvenance,
) -> Result<ReceivedRecord, String> {
    match provenance.unwrapped_with {
        TransitUnwrap::Bootstrap => {
            if !connection::connection_request::codec::is_request(&bytes) {
                return Err("bootstrap transit only carries connection requests".to_string());
            }
            let record = connection::connection_request::codec::record_from_bytes(bytes)?;
            return Ok(ReceivedRecord::with_receive(
                record,
                ReceiveMetadata::bootstrap_invite(
                    provenance.origin,
                    provenance.local_endpoint,
                    provenance.sender_endpoint,
                    provenance.remember_route,
                ),
            ));
        }
        TransitUnwrap::Connection { connection_id } => {
            if connection::connection_request::codec::is_request(&bytes) {
                return Err("connection transit cannot carry connection requests".to_string());
            }
            if connection::connection_response::codec::is_response(&bytes) {
                let record = connection::connection_response::codec::record_from_bytes(bytes)?;
                return Ok(ReceivedRecord::with_receive(
                    record,
                    ReceiveMetadata::endpoint_receive(
                        provenance.origin,
                        provenance.local_endpoint,
                        provenance.sender_endpoint,
                        provenance.remember_route,
                    ),
                ));
            }
            if sync::is_connection_scoped_event(&bytes) {
                return sync::inbound_record_from_connection_bytes(connection_id, bytes)
                    .map(ReceivedRecord::new);
            }
        }
    }
    let TransitUnwrap::Connection { .. } = provenance.unwrapped_with else {
        return Err("bootstrap transit only carries connection requests".to_string());
    };
    let record = record_from_bytes(bytes)?;
    if !record.scope.is_shared() {
        return Err(
            "connection transit only accepts shared or connection-scoped events".to_string(),
        );
    }
    let workspace_id = record
        .workspace_id
        .ok_or_else(|| "transit shared in requires a workspace".to_string())?;
    let allowed_workspaces = identity::endpoint_shared::schema::mutual_workspace_ids(
        store,
        provenance.local_endpoint,
        provenance.sender_endpoint,
    )?;
    if !allowed_workspaces
        .iter()
        .any(|allowed| allowed == &workspace_id)
    {
        return Err("transit shared in rejected event outside sender workspace".to_string());
    }
    Ok(ReceivedRecord::new(record))
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    // Connection bootstrap records use a magic prefix. Ordinary shared/local
    // events and connection-scoped sync events use a single leading type tag.
    if connection::connection_request::codec::is_request(&bytes) {
        return connection::connection_request::codec::record_from_bytes(bytes);
    }
    if connection::connection_response::codec::is_response(&bytes) {
        return connection::connection_response::codec::record_from_bytes(bytes);
    }
    if sync::is_connection_scoped_event(&bytes) {
        return sync::record_from_bytes(bytes);
    }
    let tag = bytes
        .first()
        .ok_or_else(|| "empty event bytes".to_string())?;
    match *tag {
        identity::admin::codec::TYPE_ADMIN => Err("admin must be signed".to_string()),
        identity::device_invite::codec::TYPE_DEVICE_INVITE => {
            Err("device_invite must be signed".to_string())
        }
        identity::endpoint::codec::TYPE_LOCAL_ENDPOINT => {
            identity::endpoint::codec::record_from_bytes(bytes)
        }
        identity::signed::codec::TYPE_SIGNED => identity::signed_record_from_bytes(bytes),
        identity::invite::codec::TYPE_INVITE_SECRET => {
            identity::invite::codec::record_from_bytes(bytes)
        }
        identity::workspace::codec::TYPE_WORKSPACE => {
            identity::workspace::codec::record_from_bytes(bytes)
        }
        sync::compare::codec::TYPE_SYNC_COMPARE => sync::compare::codec::record_from_bytes(bytes),
        sync::have_id::codec::TYPE_SYNC_HAVE_ID => sync::have_id::codec::record_from_bytes(bytes),
        sync::need_id::codec::TYPE_SYNC_NEED_ID => sync::need_id::codec::record_from_bytes(bytes),
        content::content_event::codec::TYPE_CONTENT => Err("content must be signed".to_string()),
        content::content_event::codec::TYPE_SIGNED_CONTENT => {
            content::content_event::codec::signed_record_from_bytes(bytes)
        }
        test_events::event_with_deps::codec::TYPE_EVENT_WITH_DEPS => {
            test_events::event_with_deps::codec::record_from_bytes(bytes)
        }
        test_events::event_with_deps::codec::TYPE_STAGED_EVENT_WITH_DEPS => {
            test_events::event_with_deps::codec::staged_record_from_bytes(bytes)
        }
        other => Err(format!("unknown event type {other}")),
    }
}
