//! Event-module registry and cross-domain protocol facade.
//!
//! Leaf modules own concrete event syntax and projection rules. Domain workers
//! own active work such as unwrap, wrap, and sync comparison. This registry is
//! the narrow place where those independent pieces are selected by tag and
//! composed into user-facing commands.
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
pub mod worker;

use std::net::SocketAddr;

use crate::core::network_queues::{self, NetworkTarget, OutboundNetworkRow};
use crate::core::store::{Schema, Store};
use crate::protocol::event_modules::worker::{
    CommandOutput, EventRegistry, EventWithContext, ProjectionOutput, ProposedEvent,
};
use types::EventRecord;

#[derive(Debug, Clone, Copy, Default)]
pub struct Modules;

/// Opaque bytes prepared for one route after draining protocol outbox rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSync {
    pub target: NetworkTarget,
    pub outgoing: Vec<OutboundNetworkRow>,
    pub sent_outbox: Vec<Vec<Vec<u8>>>,
    pub sent_events: usize,
}

impl Modules {
    pub fn new() -> Self {
        Self
    }

    pub fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        record_from_bytes(bytes)
    }

    pub fn create_invite(
        &self,
        store: &Store,
        public_addr: SocketAddr,
    ) -> Result<CommandOutput<String>, String> {
        // Invites depend on a local endpoint. If none exists yet, the endpoint
        // command is proposed first and the invite command follows in the same
        // admitted batch.
        let local = self.local_keypair(store)?;
        let invite = identity::invite::commands::create(local.value, public_addr);
        Ok(merge_outputs(local.events, invite))
    }

    pub fn invite_addr(&self, invite: &str) -> Result<SocketAddr, String> {
        identity::invite::commands::addr(invite)
    }

    pub fn generate_content(
        &self,
        store: &Store,
        workspace_id: types::EventId,
        num_events: usize,
        event_size: usize,
    ) -> Result<CommandOutput<content::content_event::commands::GenerateReport>, String> {
        let local = self.existing_local_keypair(store)?;
        let membership_key = identity::endpoint_shared::schema::endpoint_membership_key(
            local.endpoint,
            workspace_id,
        );
        let membership_bytes = store
            .table_row(
                identity::endpoint_shared::schema::ENDPOINT_MEMBERSHIPS,
                &membership_key,
            )
            .map_err(|err| format!("load local endpoint membership: {err}"))?
            .ok_or_else(|| "local endpoint is not joined to workspace".to_string())?;
        let membership = identity::endpoint_shared::schema::decode_endpoint_membership_row(
            &membership_key,
            &membership_bytes,
        )?;
        if membership.signing_public_key != local.signing_public_key {
            return Err(
                "local endpoint signing key does not match workspace membership".to_string(),
            );
        }
        let start =
            content::content_event::schema::max_timestamp_for_workspace(store, workspace_id)?
                .saturating_add(1);
        content::content_event::commands::generate(
            workspace_id,
            membership.endpoint_shared_id,
            local.signing_secret,
            start,
            num_events,
            event_size,
        )
    }

    pub fn stage_event_with_deps(
        &self,
        store: &Store,
        events: usize,
        deps_per_event: usize,
    ) -> Result<CommandOutput<test_events::event_with_deps::commands::StageReport>, String> {
        let start = schema::max_timestamp(store)
            .map_err(|err| format!("load max timestamp: {err}"))?
            .saturating_add(1);
        test_events::event_with_deps::commands::stage(events, deps_per_event, start)
    }

    pub fn staged_event_with_deps_records(
        &self,
        store: &Store,
    ) -> Result<Vec<EventRecord>, String> {
        test_events::event_with_deps::queries::staged_records(store)
    }

    pub fn create_connection_request(
        &self,
        store: &Store,
        invite: &str,
    ) -> Result<CommandOutput<connection::connection_request::commands::OutboundRequest>, String>
    {
        let local = self.local_keypair(store)?;
        let request = connection::connection_request::commands::create(local.value, invite)?;
        Ok(merge_outputs(local.events, request))
    }

    pub fn start_sync(
        &self,
        store: &Store,
    ) -> Result<CommandOutput<sync::worker::SyncStartReport>, String> {
        match sync::worker::run(store, sync::worker::Work::Start)? {
            sync::worker::Output::Started(output) => Ok(output),
            sync::worker::Output::DrainedInboundSync(_) => {
                Err("sync worker returned non-start output".to_string())
            }
        }
    }

    pub fn drain_outbox_routes(&self, store: &Store) -> Result<Vec<OutboundSync>, String> {
        let local = self.existing_local_keypair(store)?;
        let output = connection::worker::run(
            store,
            self,
            connection::worker::Work::DrainOutboxRoutes { local },
        )?;
        let connection::worker::Output::OutboundRoutes(outbound) = output else {
            return Err("connection worker returned non-outbox-routes output".to_string());
        };
        Ok(outbound
            .into_iter()
            .map(|outbound| OutboundSync {
                target: NetworkTarget::new(outbound.target),
                outgoing: network_queues::outbound_rows(
                    NetworkTarget::new(outbound.target),
                    outbound.outgoing,
                ),
                sent_outbox: outbound.sent_outbox,
                sent_events: 0,
            })
            .collect())
    }

    pub fn mark_outbox_sent(&self, store: &Store, sent_outbox: Vec<Vec<u8>>) -> Result<(), String> {
        let output = connection::worker::run(
            store,
            self,
            connection::worker::Work::MarkOutboxSent { sent_outbox },
        )?;
        let connection::worker::Output::OutboxMarked = output else {
            return Err("connection worker returned non-mark-outbox output".to_string());
        };
        Ok(())
    }

    pub fn connection_count(&self, store: &Store) -> Result<usize, String> {
        connection::queries::connection_count(store)
    }

    pub fn connection_event_count(&self, store: &Store) -> Result<usize, String> {
        connection::queries::connection_event_count(store)
    }

    fn local_keypair(
        &self,
        store: &Store,
    ) -> Result<CommandOutput<identity::endpoint::types::EndpointKeypair>, String> {
        match identity::endpoint::commands::local_keypair(store)? {
            Some(local) => Ok(CommandOutput::new(local)),
            None => Ok(identity::endpoint::commands::create_local_keypair()),
        }
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

    pub(crate) fn existing_local_keypair(
        &self,
        store: &Store,
    ) -> Result<identity::endpoint::types::EndpointKeypair, String> {
        identity::endpoint::commands::local_keypair(store)?
            .ok_or_else(|| "local endpoint is missing".to_string())
    }
}

impl identity::endpoint::commands::LocalEndpointRead for Store {
    fn local_endpoint_secret(&self) -> Result<Option<Vec<u8>>, String> {
        self.table_row(identity::endpoint::schema::LOCAL_ENDPOINT_SECRET, b"local")
            .map_err(|err| format!("load local endpoint secret: {err}"))
    }

    fn local_endpoint(&self) -> Result<Option<Vec<u8>>, String> {
        self.table_row(identity::endpoint::schema::LOCAL_ENDPOINT, b"local")
            .map_err(|err| format!("load local endpoint: {err}"))
    }

    fn local_endpoint_signing_public_key(&self) -> Result<Option<Vec<u8>>, String> {
        self.table_row(
            identity::endpoint::schema::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY,
            b"local",
        )
        .map_err(|err| format!("load local endpoint signing public key: {err}"))
    }

    fn local_endpoint_signing_secret(&self) -> Result<Option<Vec<u8>>, String> {
        self.table_row(
            identity::endpoint::schema::LOCAL_ENDPOINT_SIGNING_SECRET,
            b"local",
        )
        .map_err(|err| format!("load local endpoint signing secret: {err}"))
    }
}

impl identity::endpoint_shared::commands::EndpointMembershipRead for Store {
    fn endpoint_membership(
        &self,
        endpoint_id: identity::endpoint::types::EndpointId,
        workspace_id: types::EventId,
    ) -> Result<Option<Vec<u8>>, String> {
        self.table_row(
            identity::endpoint_shared::schema::ENDPOINT_MEMBERSHIPS,
            &identity::endpoint_shared::schema::endpoint_membership_key(endpoint_id, workspace_id),
        )
        .map_err(|err| format!("load endpoint membership: {err}"))
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
    out.extend_from_slice(sync::schema::SCHEMAS);
    out.extend_from_slice(test_events::event_with_deps::schema::SCHEMAS);
    out
}

impl EventRegistry for Modules {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.record_from_bytes(bytes)
    }

    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        self.project_record(store, event)
    }
}

fn merge_outputs<T>(
    mut events: Vec<ProposedEvent>,
    mut output: CommandOutput<T>,
) -> CommandOutput<T> {
    events.append(&mut output.events);
    output.events = events;
    output
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    // Connection bootstrap records use a magic prefix. Ordinary shared/local
    // events and connection-scoped sync events use a single leading type tag.
    if connection::connection_request::codec::is_request(&bytes) {
        return connection::connection_request::codec::record_from_bytes(bytes);
    }
    if connection::connection_ack::codec::is_ack(&bytes) {
        return connection::connection_ack::codec::record_from_bytes(bytes);
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
