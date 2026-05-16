//! Runtime bindings for the concrete `match` protocol.
//!
//! Core owns the runtime mechanics. This module supplies the protocol-specific
//! projector router, matcher set, handler set, schema sources, and atomic row
//! tables needed by `core::runtime::Runtime<Protocol>`.

use crate::core::context::Role;
use crate::core::daemon::TickReport;
use crate::core::facts::{Fact, FactScope};
use crate::core::handler_dispatch::HandlerContext;
use crate::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use crate::core::network_queues;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::core::runtime::{RuntimeHandlers, RuntimeMatchers, RuntimeProtocol};
use crate::core::schema_dsl::{
    CORE_SCHEMA_SOURCE, EVENT_MODULES_SCHEMA_SOURCE, HANDLERS_SCHEMA_SOURCE,
};
use crate::core::store::Store;
use crate::core::store::TableName;
use crate::core::tcp;
use crate::core::wake_loop::{DispatchReport, WakeLoop};
use crate::event_modules::{
    connection_ephemeral_secret, connection_request, connection_response, content_event,
    content_file, content_file_deletion, content_file_slice, content_message,
    content_message_deletion, content_reaction, disappearing_messages_setting, encryption,
    identity_admin, identity_device_invite, identity_endpoint, identity_endpoint_shared,
    identity_invite, identity_invite_accepted, identity_invite_server, identity_matchers,
    identity_user, identity_user_invite, identity_workspace, local_history_node_secret,
    removal_frontier, sealed_message, signed_fact, sync, sync_compare, sync_encrypted_root,
    sync_have_id, sync_key_wrap_available, sync_need_id, sync_range_request, sync_shared_event,
    transit_received,
};
use crate::handlers::{
    bootstrap_send, connection_response as connection_response_handler, handle_sync,
    materialize_key_wraps, network_send, purge_cascade, purge_event,
    purge_retired_recipient_material, receive_transit, retention_expiry, retention_floor,
    sync_index_update, transit, unwrap_key_wrap,
};
use std::collections::BTreeSet;

pub type ProtocolRuntime = crate::core::runtime::Runtime<super::Protocol>;

impl crate::core::runtime::Runtime<super::Protocol> {
    pub fn daemon_tick(
        &mut self,
        listener: &tcp::Listener,
        work_limit: usize,
    ) -> Result<TickReport, String> {
        self.reload_wake_loop()?;
        let accepted = listener.accept_available(self.store())?;
        let inbound = network_queues::claim_inbound(self.store(), work_limit)?;
        for row in &inbound {
            self.submit_intent(receive_transit::receive_transit_frame_intent(
                receive_transit::ReceiveTransitFrame {
                    frame: row.bytes.clone(),
                    origin_addr: transit_received::addr::canonical_origin_addr_bytes(
                        row.source.addr(),
                    ),
                    received_at_local_ms: now_ms(),
                },
            )?)?;
        }
        network_queues::delete_inbound(self.store(), &inbound)?;

        let projection_before_handlers = self.drain_projection_until_idle(4, work_limit)?;
        let dispatched = self.dispatch_intents(work_limit)?;
        let seeded_sync = self.seed_sync_have_ids(work_limit)?;
        let projection_after_seed = self.drain_projection_until_idle(4, work_limit)?;
        let dispatched_after_seed = self.dispatch_intents(work_limit)?;
        let projection_after_handlers = self.drain_projection_until_idle(4, work_limit)?;
        self.save()?;

        Ok(TickReport {
            accepted_connections: accepted.accepted_connections,
            received_frames: accepted.value.received_frames,
            projections: projection_before_handlers.projections
                + projection_after_seed.projections
                + projection_after_handlers.projections,
            handled_intents: dispatched.handled + dispatched_after_seed.handled,
            emitted_facts: dispatched.facts + dispatched_after_seed.facts + seeded_sync,
            emitted_intents: dispatched.intents + dispatched_after_seed.intents,
        })
    }

    fn seed_sync_have_ids(&mut self, limit: usize) -> Result<usize, String> {
        let mut seeded = 0usize;
        let Some(local_endpoint) = identity_endpoint::local_endpoint::local_endpoint(self.store())?
        else {
            return Ok(0);
        };
        let endpoint_memberships = endpoint_memberships(self.store())?;
        let connections = self
            .store()
            .table_rows(connection_response::rows::CONNECTION_RESPONSE_ROWS)
            .map_err(|err| format!("load connection rows for sync seed: {err}"))?;
        if connections.is_empty() {
            return Ok(0);
        }
        let facts = self.facts().cloned().collect::<Vec<_>>();
        for (connection_key, connection_value) in connections {
            let row = connection_response::rows::decode_connection_response_row(
                &connection_key,
                &connection_value,
            )?;
            let Some(remote_endpoint) =
                remote_endpoint_for_connection(&row, local_endpoint.endpoint)
            else {
                continue;
            };
            for fact in &facts {
                if seeded >= limit {
                    return Ok(seeded);
                }
                if !is_sync_seed_fact(fact)
                    || !may_seed_fact_to_endpoint(fact, remote_endpoint, &endpoint_memberships)
                {
                    continue;
                }
                let have = sync_have_id::fact::SyncHaveIdFact {
                    connection_id: row.connection_id,
                    timestamp: fact.timestamp,
                    event_id: fact.id,
                };
                let have_fact = Fact::new(
                    FactScope::Global,
                    fact.timestamp,
                    sync_have_id::layout::encode_fact(&have)?,
                );
                if self.submit_fact(have_fact.clone()) {
                    self.submit_intent(transit::send_on_connection_intent(
                        transit::TransitSendOnConnection {
                            connection_id: row.connection_id,
                            fact_ids: vec![have_fact.id],
                        },
                    ))?;
                    seeded += 1;
                }
            }
        }
        Ok(seeded)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn is_sync_seed_fact(fact: &Fact) -> bool {
    if fact.scope == FactScope::Local {
        return false;
    }
    let Some(tag) = fact.bytes.first().copied() else {
        return false;
    };
    if matches!(
        tag,
        sync_compare::layout::TYPE_SYNC_COMPARE
            | sync_have_id::layout::TYPE_SYNC_HAVE_ID
            | sync_need_id::layout::TYPE_SYNC_NEED_ID
            | sync_range_request::layout::TYPE_SYNC_RANGE_REQUEST
            | sync_shared_event::layout::TYPE_SHARED_EVENT
            | sync_encrypted_root::layout::TYPE_ENCRYPTED_ROOT
            | sync_key_wrap_available::layout::TYPE_KEY_WRAP_AVAILABLE
    ) {
        return false;
    }
    crate::event_modules::transit::create::require_sendable_fact(fact).is_ok()
}

fn remote_endpoint_for_connection(
    row: &connection_response::rows::ConnectionResponseRow,
    local_endpoint: [u8; 32],
) -> Option<[u8; 32]> {
    if row.from_endpoint == local_endpoint {
        Some(row.to_endpoint)
    } else if row.to_endpoint == local_endpoint {
        Some(row.from_endpoint)
    } else {
        None
    }
}

fn endpoint_memberships(store: &Store) -> Result<BTreeSet<([u8; 32], [u8; 32])>, String> {
    let rows = store
        .table_rows(identity_endpoint_shared::rows::ENDPOINT_SHARED_ROWS)
        .map_err(|err| format!("load endpoint membership rows for sync seed: {err}"))?;
    rows.into_iter()
        .map(|(key, value)| {
            identity_endpoint_shared::rows::decode_endpoint_shared_row(&key, &value)
                .map(|row| (row.workspace_id, row.endpoint_id))
        })
        .collect()
}

fn may_seed_fact_to_endpoint(
    fact: &Fact,
    remote_endpoint: [u8; 32],
    endpoint_memberships: &BTreeSet<([u8; 32], [u8; 32])>,
) -> bool {
    match &fact.scope {
        FactScope::Global => true,
        FactScope::Local => false,
        FactScope::Scoped { kind, id } if kind.as_str() == "workspace" => {
            endpoint_memberships.contains(&(*id, remote_endpoint))
        }
        FactScope::Scoped { .. } => false,
    }
}

const SCHEMA_SOURCES: &[&str] = &[
    CORE_SCHEMA_SOURCE,
    EVENT_MODULES_SCHEMA_SOURCE,
    HANDLERS_SCHEMA_SOURCE,
];

const ATOMIC_ROW_TABLES: &[TableName] = &[
    connection_ephemeral_secret::rows::CONNECTION_EPHEMERAL_SECRET_ROWS,
    connection_request::rows::CONNECTION_REQUEST_ROWS,
    connection_response::rows::CONNECTION_RESPONSE_ROWS,
    content_event::rows::CONTENT_EVENT_ROWS,
    content_file::rows::FILE_ROWS,
    content_file_deletion::rows::FILE_DELETION_ROWS,
    content_file_slice::rows::FILE_SLICE_ROWS,
    content_message::rows::CONTENT_MESSAGE_ROWS,
    content_message_deletion::rows::MESSAGE_DELETION_ROWS,
    content_reaction::rows::REACTION_ROWS,
    disappearing_messages_setting::rows::DISAPPEARING_MESSAGES_SETTING_ROWS,
    encryption::rows::KEY_WRAP_ROWS,
    identity_admin::rows::ADMIN_ROWS,
    identity_device_invite::rows::DEVICE_INVITE_ROWS,
    identity_endpoint::rows::LOCAL_ENDPOINT_ROWS,
    identity_endpoint::rows::LOCAL_ENDPOINT_SECRET_ROWS,
    identity_endpoint::rows::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
    identity_endpoint::rows::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS,
    identity_endpoint_shared::rows::ENDPOINT_SHARED_ROWS,
    identity_invite::rows::INVITE_SECRET_ROWS,
    identity_invite_accepted::rows::INVITE_ACCEPTED_ROWS,
    identity_invite_server::rows::INVITE_SERVER_ROWS,
    identity_user::rows::USER_ROWS,
    identity_user_invite::rows::USER_INVITE_ROWS,
    identity_workspace::rows::WORKSPACE_ROWS,
    local_history_node_secret::rows::LOCAL_HISTORY_NODE_SECRET_ROWS,
    removal_frontier::rows::REMOVAL_FRONTIER_ROWS,
    sealed_message::rows::MESSAGE_ROWS,
    sealed_message::rows::OPENED_MESSAGE_ROWS,
    sealed_message::rows::MESSAGE_TOMBSTONE_ROWS,
    sealed_message::rows::SEALED_MESSAGE_ROWS,
    sync_compare::rows::SYNC_COMPARE_ROWS,
    sync_have_id::rows::SYNC_HAVE_ID_ROWS,
    sync_need_id::rows::SYNC_NEED_ID_ROWS,
];

impl RuntimeProtocol for super::Protocol {
    type Projector = ProtocolProjector;
    type Matchers = ProtocolContextMatchers;
    type Handlers = ProtocolHandlers;

    fn schema_sources() -> &'static [&'static str] {
        SCHEMA_SOURCES
    }

    fn atomic_row_tables() -> &'static [TableName] {
        ATOMIC_ROW_TABLES
    }

    fn projector() -> Self::Projector {
        ProtocolProjector
    }

    fn matchers() -> Self::Matchers {
        ProtocolContextMatchers::new()
    }

    fn handlers() -> Self::Handlers {
        ProtocolHandlers::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProtocolProjector;

impl Projector for ProtocolProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let Some(tag) = fact.bytes.first().copied() else {
            return Err("cannot project empty fact bytes".to_string());
        };
        match tag {
            connection_ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET => {
                connection_ephemeral_secret::project::ConnectionEphemeralSecretProjector::new()
                    .project(fact, context)
            }
            connection_request::layout::TYPE_CONNECTION_REQUEST => {
                connection_request::project::ConnectionRequestProjector::new()
                    .project(fact, context)
            }
            connection_response::layout::TYPE_CONNECTION_RESPONSE => {
                connection_response::project::ConnectionResponseProjector::new()
                    .project(fact, context)
            }
            content_event::layout::TYPE_CONTENT_EVENT => {
                content_event::project::ContentEventProjector::new().project(fact, context)
            }
            content_file::layout::TYPE_CONTENT_FILE => {
                content_file::project::ContentFileProjector::new().project(fact, context)
            }
            content_file_deletion::layout::TYPE_CONTENT_FILE_DELETION => {
                content_file_deletion::project::ContentFileDeletionProjector::new()
                    .project(fact, context)
            }
            content_file_slice::layout::TYPE_CONTENT_FILE_SLICE => {
                content_file_slice::project::ContentFileSliceProjector::new().project(fact, context)
            }
            content_message::layout::TYPE_CONTENT_MESSAGE => {
                content_message::project::ContentMessageProjector::new().project(fact, context)
            }
            content_message_deletion::layout::TYPE_CONTENT_MESSAGE_DELETION => {
                content_message_deletion::project::ContentMessageDeletionProjector::new()
                    .project(fact, context)
            }
            content_reaction::layout::TYPE_CONTENT_REACTION => {
                content_reaction::project::ContentReactionProjector::new().project(fact, context)
            }
            encryption::layout::TYPE_RECIPIENT_KEY
            | encryption::layout::TYPE_REMOVAL_FRONTIER
            | encryption::layout::TYPE_LOCAL_KEY_SECRET
            | encryption::layout::TYPE_LOCAL_HISTORY_NODE_SECRET
            | encryption::layout::TYPE_KEY_REQUEST
            | encryption::layout::TYPE_KEY_WRAP
            | encryption::layout::TYPE_LOCAL_RECIPIENT_KEY => {
                encryption::project::EncryptionProjector::new().project(fact, context)
            }
            identity_endpoint::layout::TYPE_LOCAL_ENDPOINT => {
                identity_endpoint::project::EndpointProjector::new().project(fact, context)
            }
            identity_invite::layout::TYPE_INVITE_SECRET => {
                identity_invite::project::InviteSecretProjector::new().project(fact, context)
            }
            identity_workspace::layout::TYPE_WORKSPACE => {
                identity_workspace::project::WorkspaceProjector::new().project(fact, context)
            }
            signed_fact::layout::TYPE_SIGNED_FACT => {
                let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)?;
                match envelope.inner_type {
                    identity_user_invite::layout::TYPE_USER_INVITE => {
                        identity_user_invite::project::UserInviteProjector::new()
                            .project(fact, context)
                    }
                    identity_user::layout::TYPE_USER => {
                        identity_user::project::UserProjector::new().project(fact, context)
                    }
                    identity_admin::layout::TYPE_ADMIN => {
                        identity_admin::project::AdminProjector::new().project(fact, context)
                    }
                    identity_endpoint_shared::layout::TYPE_ENDPOINT_SHARED => {
                        identity_endpoint_shared::project::EndpointSharedProjector::new()
                            .project(fact, context)
                    }
                    identity_device_invite::layout::TYPE_DEVICE_INVITE => {
                        identity_device_invite::project::DeviceInviteProjector::new()
                            .project(fact, context)
                    }
                    identity_invite_server::layout::TYPE_INVITE_SERVER => {
                        identity_invite_server::project::InviteServerProjector::new()
                            .project(fact, context)
                    }
                    encryption::layout::TYPE_KEY_WRAP => {
                        encryption::project::EncryptionProjector::new().project(fact, context)
                    }
                    sealed_message::layout::TYPE_SEALED_MESSAGE => {
                        sealed_message::project::SealedMessageProjector::new()
                            .project(fact, context)
                    }
                    inner_type => Err(format!(
                        "no target projector registered for signed inner fact tag {inner_type}"
                    )),
                }
            }
            signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET => {
                signed_fact::project::SignedFactProjector::new().project(fact, context)
            }
            identity_device_invite::layout::TYPE_DEVICE_INVITE => {
                identity_device_invite::project::DeviceInviteProjector::new().project(fact, context)
            }
            identity_endpoint_shared::layout::TYPE_ENDPOINT_SHARED => {
                identity_endpoint_shared::project::EndpointSharedProjector::new()
                    .project(fact, context)
            }
            identity_invite_server::layout::TYPE_INVITE_SERVER => {
                identity_invite_server::project::InviteServerProjector::new().project(fact, context)
            }
            identity_admin::layout::TYPE_ADMIN => {
                identity_admin::project::AdminProjector::new().project(fact, context)
            }
            sealed_message::layout::TYPE_SEALED_MESSAGE
            | sealed_message::layout::TYPE_SIGNER_PUBKEY
            | sealed_message::layout::TYPE_SECRET_NODE => {
                sealed_message::project::SealedMessageProjector::new().project(fact, context)
            }
            sealed_message::layout::TYPE_MESSAGE_DELETION => {
                sealed_message::project::SealedMessageProjector::new().project(fact, context)
            }
            identity_invite_accepted::layout::TYPE_INVITE_ACCEPTED => {
                identity_invite_accepted::project::InviteAcceptedProjector::new()
                    .project(fact, context)
            }
            disappearing_messages_setting::layout::TYPE_DISAPPEARING_MESSAGES_SETTING => {
                disappearing_messages_setting::project::DisappearingMessagesSettingProjector::new()
                    .project(fact, context)
            }
            sync_range_request::layout::TYPE_SYNC_RANGE_REQUEST => {
                sync_range_request::project::SyncRangeRequestProjector::new().project(fact, context)
            }
            sync_encrypted_root::layout::TYPE_ENCRYPTED_ROOT => {
                sync_encrypted_root::project::SyncEncryptedRootProjector::new()
                    .project(fact, context)
            }
            sync_shared_event::layout::TYPE_SHARED_EVENT => {
                sync_shared_event::project::SyncSharedEventProjector::new().project(fact, context)
            }
            sync_key_wrap_available::layout::TYPE_KEY_WRAP_AVAILABLE => {
                sync_key_wrap_available::project::SyncKeyWrapAvailableProjector::new()
                    .project(fact, context)
            }
            sync_compare::layout::TYPE_SYNC_COMPARE => {
                sync_compare::project::SyncCompareProjector::new().project(fact, context)
            }
            sync_have_id::layout::TYPE_SYNC_HAVE_ID => {
                sync_have_id::project::SyncHaveIdProjector::new().project(fact, context)
            }
            sync_need_id::layout::TYPE_SYNC_NEED_ID => {
                sync_need_id::project::SyncNeedIdProjector::new().project(fact, context)
            }
            transit_received::layout::TYPE_TRANSIT_RECEIVED => {
                transit_received::project::TransitReceivedProjector::new().project(fact, context)
            }
            identity_user_invite::layout::TYPE_USER_INVITE => {
                identity_user_invite::project::UserInviteProjector::new().project(fact, context)
            }
            identity_user::layout::TYPE_USER => {
                identity_user::project::UserProjector::new().project(fact, context)
            }
            local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET => {
                local_history_node_secret::project::LocalHistoryNodeSecretProjector::new()
                    .project(fact, context)
            }
            removal_frontier::layout::TYPE_REMOVAL_FRONTIER => {
                removal_frontier::project::RemovalFrontierProjector::new().project(fact, context)
            }
            _ => Err(format!("no target projector registered for fact tag {tag}")),
        }
    }
}

pub struct ProtocolContextMatchers {
    matchers: Vec<Box<dyn ContextMatcher>>,
}

impl ProtocolContextMatchers {
    fn new() -> Self {
        let roles = [
            connection_ephemeral_secret::matchers::connection_ephemeral_secret_role(),
            connection_request::matchers::connection_invite_secret_role(),
            connection_request::matchers::connection_request_role(),
            content_file::matchers::file_role(),
            content_message::matchers::message_role(),
            content_message::matchers::deletion_role(),
            encryption::matchers::recipient_key_role(),
            encryption::matchers::frontier_role(),
            encryption::matchers::recipient_superseded_role(),
            encryption::matchers::local_recipient_key_role(),
            identity_matchers::matchers::workspace_role(),
            identity_matchers::matchers::invite_secret_role(),
            identity_matchers::matchers::user_invite_role(),
            identity_matchers::matchers::user_invite_key_role(),
            identity_matchers::matchers::invite_server_role(),
            identity_matchers::matchers::invite_server_key_role(),
            identity_matchers::matchers::user_role(),
            identity_matchers::matchers::device_invite_role(),
            identity_matchers::matchers::device_invite_key_role(),
            identity_matchers::matchers::endpoint_shared_role(),
            identity_matchers::matchers::admin_role(),
            local_history_node_secret::matchers::source_secret_role(),
            sealed_message::matchers::signer_role(),
            sealed_message::matchers::deletion_role(),
            signed_fact::matchers::local_signer_secret_role(),
            sync::matchers::exact_event_role(),
            sync::matchers::key_wrap_role(),
            transit_received::matchers::transit_received_role(),
        ];
        let mut matchers: Vec<Box<dyn ContextMatcher>> =
            roles.into_iter().map(exact_matcher).collect();
        matchers.push(Box::new(encryption::matchers::WrapSourceMatcher::new()));
        matchers.push(Box::new(
            sealed_message::matchers::SecretCoverageMatcher::new(),
        ));
        matchers.push(Box::new(sync::matchers::RangeEventMatcher::new()));
        Self { matchers }
    }

    fn matcher_refs(&self) -> Vec<&dyn ContextMatcher> {
        self.matchers
            .iter()
            .map(|matcher| matcher.as_ref() as &dyn ContextMatcher)
            .collect()
    }
}

impl RuntimeMatchers for ProtocolContextMatchers {
    fn refs(&self) -> Vec<&dyn ContextMatcher> {
        self.matcher_refs()
    }
}

fn exact_matcher(role: Role) -> Box<dyn ContextMatcher> {
    Box::new(ExactSelectorMatcher::new(role))
}

#[derive(Debug, Clone)]
pub struct ProtocolHandlers {
    bootstrap_send: bootstrap_send::BootstrapSendRequestHandler,
    connection_response: connection_response_handler::ConnectionResponseHandler,
    handle_sync: handle_sync::HandleSyncHandler,
    respond_to_sync_compare: handle_sync::RespondToSyncCompareHandler,
    request_sync_id: handle_sync::RequestSyncIdHandler,
    respond_to_sync_need: handle_sync::RespondToSyncNeedHandler,
    materialize_key_wraps: materialize_key_wraps::MaterializeKeyWrapsHandler,
    network_send: network_send::NetworkSendHandler,
    purge_cascade: purge_cascade::PurgeCascadeHandler,
    purge_event: purge_event::PurgeEventHandler,
    purge_retired_recipient_material:
        purge_retired_recipient_material::PurgeRetiredRecipientMaterialHandler,
    receive_transit: receive_transit::ReceiveTransitHandler,
    retention_expiry: retention_expiry::RetentionExpiryHandler,
    retention_floor: retention_floor::RetentionFloorHandler,
    sync_index_update: sync_index_update::SyncIndexUpdateHandler,
    transit: transit::TransitSendOnConnectionHandler,
    unwrap_key_wrap: unwrap_key_wrap::UnwrapKeyWrapHandler,
}

impl ProtocolHandlers {
    fn new() -> Self {
        Self {
            bootstrap_send: bootstrap_send::BootstrapSendRequestHandler::new(),
            connection_response: connection_response_handler::ConnectionResponseHandler::new(),
            handle_sync: handle_sync::HandleSyncHandler::new(),
            respond_to_sync_compare: handle_sync::RespondToSyncCompareHandler::new(),
            request_sync_id: handle_sync::RequestSyncIdHandler::new(),
            respond_to_sync_need: handle_sync::RespondToSyncNeedHandler::new(),
            materialize_key_wraps: materialize_key_wraps::MaterializeKeyWrapsHandler::new(),
            network_send: network_send::NetworkSendHandler::new(),
            purge_cascade: purge_cascade::PurgeCascadeHandler::new(),
            purge_event: purge_event::PurgeEventHandler::new(),
            purge_retired_recipient_material:
                purge_retired_recipient_material::PurgeRetiredRecipientMaterialHandler::new(),
            receive_transit: receive_transit::ReceiveTransitHandler::new(),
            retention_expiry: retention_expiry::RetentionExpiryHandler::new(),
            retention_floor: retention_floor::RetentionFloorHandler::new(),
            sync_index_update: sync_index_update::SyncIndexUpdateHandler::new(),
            transit: transit::TransitSendOnConnectionHandler::new(),
            unwrap_key_wrap: unwrap_key_wrap::UnwrapKeyWrapHandler::new(),
        }
    }

    fn dispatch_all(
        &self,
        wake_loop: &mut WakeLoop,
        store: &Store,
        limit_per_handler: usize,
    ) -> Result<DispatchReport, String> {
        let mut total = DispatchReport::default();
        self.dispatch_one(
            wake_loop,
            &self.bootstrap_send,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.connection_response,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.handle_sync,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.respond_to_sync_compare,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.request_sync_id,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.respond_to_sync_need,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.materialize_key_wraps,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.purge_cascade,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.purge_event,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.purge_retired_recipient_material,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.receive_transit,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.retention_expiry,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.retention_floor,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.sync_index_update,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.transit,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.network_send,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.unwrap_key_wrap,
            store,
            limit_per_handler,
            &mut total,
        )?;
        Ok(total)
    }

    fn dispatch_one(
        &self,
        wake_loop: &mut WakeLoop,
        handler: &impl crate::core::handler_dispatch::IntentHandler,
        store: &Store,
        limit: usize,
        total: &mut DispatchReport,
    ) -> Result<(), String> {
        let report = wake_loop
            .dispatch_deferred_intents_with_fact_context_and_store(handler, store, limit)?;
        total.handled += report.handled;
        total.facts += report.facts;
        total.intents += report.intents;
        if report.handled == 0 {
            let empty_context = HandlerContext::new().with_store(store);
            let report = wake_loop.dispatch_atomic_intents(handler, &empty_context, limit)?;
            total.handled += report.handled;
            total.facts += report.facts;
            total.intents += report.intents;
        }
        Ok(())
    }
}

impl RuntimeHandlers for ProtocolHandlers {
    fn dispatch(
        &self,
        wake_loop: &mut WakeLoop,
        store: &Store,
        limit_per_handler: usize,
    ) -> Result<DispatchReport, String> {
        self.dispatch_all(wake_loop, store, limit_per_handler)
    }
}
