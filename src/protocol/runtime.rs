//! Runtime bindings for the concrete `match` protocol.
//!
//! Core owns the runtime mechanics. This module supplies the protocol-specific
//! projector router, matcher set, handler set, schema sources, and atomic row
//! tables needed by `core::runtime::Runtime<Protocol>`.

use crate::core::context::Role;
use crate::core::facts::Fact;
use crate::core::handler_dispatch::HandlerContext;
use crate::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::core::runtime::{RuntimeHandlers, RuntimeMatchers, RuntimeProtocol};
use crate::core::schema_dsl::{
    CORE_SCHEMA_SOURCE, EVENT_MODULES_SCHEMA_SOURCE, HANDLERS_SCHEMA_SOURCE,
};
use crate::core::store::TableName;
use crate::core::wake_loop::{DispatchReport, WakeLoop};
use crate::event_modules::{
    connection_ephemeral_secret, connection_request, connection_response, content_event,
    content_file, content_file_deletion, content_file_slice, content_message,
    content_message_deletion, content_reaction, disappearing_messages_setting, encryption,
    identity_admin, identity_device_invite, identity_endpoint, identity_endpoint_shared,
    identity_invite, identity_invite_accepted, identity_invite_server, identity_matchers,
    identity_user, identity_user_invite, identity_workspace, local_history_node_secret,
    removal_frontier, sealed_message, signed_fact, sync, sync_compare, sync_have_id, sync_need_id,
    transit_received,
};
use crate::handlers::{
    connection_response as connection_response_handler, handle_sync, materialize_key_wraps,
    network_send, purge_cascade, purge_event, purge_retired_recipient_material, receive_transit,
    retention_expiry, retention_floor, sync_index_update, transit, unwrap_key_wrap,
};

pub type ProtocolRuntime = crate::core::runtime::Runtime<super::Protocol>;

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
            sync::layout::TYPE_SYNC_RANGE_REQUEST
            | sync::layout::TYPE_ENCRYPTED_ROOT
            | sync::layout::TYPE_SHARED_EVENT
            | sync::layout::TYPE_KEY_WRAP_AVAILABLE => {
                sync::project::SyncContextProjector::new().project(fact, context)
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
    connection_response: connection_response_handler::ConnectionResponseHandler,
    handle_sync: handle_sync::HandleSyncHandler,
    respond_to_sync_compare: handle_sync::RespondToSyncCompareHandler,
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
            connection_response: connection_response_handler::ConnectionResponseHandler::new(),
            handle_sync: handle_sync::HandleSyncHandler::new(),
            respond_to_sync_compare: handle_sync::RespondToSyncCompareHandler::new(),
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
        limit_per_handler: usize,
    ) -> Result<DispatchReport, String> {
        let mut total = DispatchReport::default();
        self.dispatch_one(
            wake_loop,
            &self.connection_response,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(wake_loop, &self.handle_sync, limit_per_handler, &mut total)?;
        self.dispatch_one(
            wake_loop,
            &self.respond_to_sync_compare,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.materialize_key_wraps,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(wake_loop, &self.network_send, limit_per_handler, &mut total)?;
        self.dispatch_one(
            wake_loop,
            &self.purge_cascade,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(wake_loop, &self.purge_event, limit_per_handler, &mut total)?;
        self.dispatch_one(
            wake_loop,
            &self.purge_retired_recipient_material,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.receive_transit,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.retention_expiry,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.retention_floor,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.sync_index_update,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(wake_loop, &self.transit, limit_per_handler, &mut total)?;
        self.dispatch_one(
            wake_loop,
            &self.unwrap_key_wrap,
            limit_per_handler,
            &mut total,
        )?;
        Ok(total)
    }

    fn dispatch_one(
        &self,
        wake_loop: &mut WakeLoop,
        handler: &impl crate::core::handler_dispatch::IntentHandler,
        limit: usize,
        total: &mut DispatchReport,
    ) -> Result<(), String> {
        let report = wake_loop.dispatch_deferred_intents_with_fact_context(handler, limit)?;
        total.handled += report.handled;
        total.facts += report.facts;
        total.intents += report.intents;
        if report.handled == 0 {
            let empty_context = HandlerContext::new();
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
        limit_per_handler: usize,
    ) -> Result<DispatchReport, String> {
        self.dispatch_all(wake_loop, limit_per_handler)
    }
}
