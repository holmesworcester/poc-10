//! Runtime bindings for the concrete `match` protocol.
//!
//! Core owns the runtime mechanics. This module supplies the protocol-specific
//! projector router, matcher set, handler set, schema sources, and atomic row
//! tables needed by `core::runtime::Runtime<Protocol>`.

use crate::core::context::Role;
use crate::core::daemon::TickReport;
use crate::core::facts::Fact;
use crate::core::logical_clock;
use crate::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use crate::core::network_queues;
use crate::core::projection::{
    EnvelopeRoute, FactRoute, ProjectionContext, ProjectionOutput, Projector, RouterProjector,
};
use crate::core::runtime::{HandlerRoute, HandlerSet, RuntimeMatchers, RuntimeProtocol};
use crate::core::schema_dsl::{
    CORE_SCHEMA_SOURCE, EVENT_MODULES_SCHEMA_SOURCE, HANDLERS_SCHEMA_SOURCE,
};
use crate::core::store::TableName;
use crate::core::tcp;
use crate::event_modules::{
    connection_ephemeral_secret, connection_request, connection_response, content_event,
    content_file, content_file_deletion, content_file_slice, content_message,
    content_message_deletion, content_reaction, disappearing_messages_setting, encryption,
    identity_admin, identity_device_invite, identity_endpoint, identity_endpoint_shared,
    identity_invite, identity_invite_accepted, identity_invite_server, identity_user,
    identity_user_invite, identity_workspace, local_history_node_secret, removal_frontier,
    sealed_message, signed_fact, sync, sync_compare, sync_encrypted_root, sync_have_id,
    sync_key_wrap_available, sync_need_id, sync_range_request, sync_shared_event, transit_received,
};
use crate::handlers::{
    bootstrap_send, connection_response as connection_response_handler, handle_sync,
    materialize_key_wraps, network_send, purge_cascade, purge_event,
    purge_retired_recipient_material, receive_transit, retention_expiry, retention_floor,
    sync_index_update, transit, unwrap_key_wrap,
};

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

        self.wake_time_range(
            sealed_message::matchers::expiration_timeline(),
            None,
            current_minute(self.store())?,
            work_limit,
        );
        let projection_before_handlers = self.drain_projection_until_idle(4, work_limit)?;
        let dispatched = self.dispatch_intents(work_limit)?;
        let projection_after_handlers = self.drain_projection_until_idle(4, work_limit)?;
        self.save()?;

        Ok(TickReport {
            accepted_connections: accepted.accepted_connections,
            received_frames: accepted.value.received_frames,
            projections: projection_before_handlers.projections
                + projection_after_handlers.projections,
            handled_intents: dispatched.handled,
            emitted_facts: dispatched.facts,
            emitted_intents: dispatched.intents,
        })
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn current_minute(store: &crate::core::store::Store) -> Result<u64, String> {
    let now_ms = logical_clock::logical_time(store)?.unwrap_or_else(now_ms);
    Ok(now_ms / 60_000)
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
    type Handlers = HandlerSet;

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
        HandlerSet::new(HANDLER_ROUTES)
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
        let output = RouterProjector::new(FACT_ROUTES, ENVELOPE_ROUTES).project(fact, context)?;
        Ok(with_sync_index_update(output, fact))
    }
}

fn with_sync_index_update(output: ProjectionOutput, fact: &Fact) -> ProjectionOutput {
    if !handle_sync::is_sync_seed_fact(fact) {
        return output;
    }
    output.intent(sync_index_update::record_indexed_event_intent(
        sync_index_update::RecordIndexedEvent {
            event_id: fact.id,
            timestamp_ms: fact.timestamp,
        },
    ))
}

macro_rules! projector_route {
    ($name:ident, $projector:path) => {
        fn $name(fact: &Fact, context: &ProjectionContext) -> Result<ProjectionOutput, String> {
            <$projector>::new().project(fact, context)
        }
    };
}

projector_route!(
    project_connection_ephemeral_secret,
    connection_ephemeral_secret::project::ConnectionEphemeralSecretProjector
);
projector_route!(
    project_connection_request,
    connection_request::project::ConnectionRequestProjector
);
projector_route!(
    project_connection_response,
    connection_response::project::ConnectionResponseProjector
);
projector_route!(
    project_content_event,
    content_event::project::ContentEventProjector
);
projector_route!(
    project_content_file,
    content_file::project::ContentFileProjector
);
projector_route!(
    project_content_file_deletion,
    content_file_deletion::project::ContentFileDeletionProjector
);
projector_route!(
    project_content_file_slice,
    content_file_slice::project::ContentFileSliceProjector
);
projector_route!(
    project_content_message,
    content_message::project::ContentMessageProjector
);
projector_route!(
    project_content_message_deletion,
    content_message_deletion::project::ContentMessageDeletionProjector
);
projector_route!(
    project_content_reaction,
    content_reaction::project::ContentReactionProjector
);
projector_route!(project_encryption, encryption::project::EncryptionProjector);
projector_route!(
    project_endpoint,
    identity_endpoint::project::EndpointProjector
);
projector_route!(
    project_invite,
    identity_invite::project::InviteSecretProjector
);
projector_route!(
    project_workspace,
    identity_workspace::project::WorkspaceProjector
);
projector_route!(
    project_signed_fact,
    signed_fact::project::SignedFactProjector
);
projector_route!(
    project_device_invite,
    identity_device_invite::project::DeviceInviteProjector
);
projector_route!(
    project_endpoint_shared,
    identity_endpoint_shared::project::EndpointSharedProjector
);
projector_route!(
    project_invite_server,
    identity_invite_server::project::InviteServerProjector
);
projector_route!(project_admin, identity_admin::project::AdminProjector);
projector_route!(
    project_sealed_message,
    sealed_message::project::SealedMessageProjector
);
projector_route!(
    project_invite_accepted,
    identity_invite_accepted::project::InviteAcceptedProjector
);
projector_route!(
    project_disappearing_messages_setting,
    disappearing_messages_setting::project::DisappearingMessagesSettingProjector
);
projector_route!(
    project_sync_range_request,
    sync_range_request::project::SyncRangeRequestProjector
);
projector_route!(
    project_sync_encrypted_root,
    sync_encrypted_root::project::SyncEncryptedRootProjector
);
projector_route!(
    project_sync_shared_event,
    sync_shared_event::project::SyncSharedEventProjector
);
projector_route!(
    project_sync_key_wrap_available,
    sync_key_wrap_available::project::SyncKeyWrapAvailableProjector
);
projector_route!(
    project_sync_compare,
    sync_compare::project::SyncCompareProjector
);
projector_route!(
    project_sync_have_id,
    sync_have_id::project::SyncHaveIdProjector
);
projector_route!(
    project_sync_need_id,
    sync_need_id::project::SyncNeedIdProjector
);
projector_route!(
    project_transit_received,
    transit_received::project::TransitReceivedProjector
);
projector_route!(
    project_user_invite,
    identity_user_invite::project::UserInviteProjector
);
projector_route!(project_user, identity_user::project::UserProjector);
projector_route!(
    project_local_history_node_secret,
    local_history_node_secret::project::LocalHistoryNodeSecretProjector
);
projector_route!(
    project_removal_frontier,
    removal_frontier::project::RemovalFrontierProjector
);

fn signed_effective_tag(fact: &Fact) -> Result<u8, String> {
    Ok(signed_fact::layout::decode_signed_fact(&fact.bytes)?.inner_type)
}

const ENVELOPE_ROUTES: &[EnvelopeRoute] = &[EnvelopeRoute {
    outer_tag: signed_fact::layout::TYPE_SIGNED_FACT,
    effective_tag: signed_effective_tag,
}];

const FACT_ROUTES: &[FactRoute] = &[
    FactRoute {
        tag: connection_ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET,
        projector: project_connection_ephemeral_secret,
    },
    FactRoute {
        tag: connection_request::layout::TYPE_CONNECTION_REQUEST,
        projector: project_connection_request,
    },
    FactRoute {
        tag: connection_response::layout::TYPE_CONNECTION_RESPONSE,
        projector: project_connection_response,
    },
    FactRoute {
        tag: content_event::layout::TYPE_CONTENT_EVENT,
        projector: project_content_event,
    },
    FactRoute {
        tag: content_file::layout::TYPE_CONTENT_FILE,
        projector: project_content_file,
    },
    FactRoute {
        tag: content_file_deletion::layout::TYPE_CONTENT_FILE_DELETION,
        projector: project_content_file_deletion,
    },
    FactRoute {
        tag: content_file_slice::layout::TYPE_CONTENT_FILE_SLICE,
        projector: project_content_file_slice,
    },
    FactRoute {
        tag: content_message::layout::TYPE_CONTENT_MESSAGE,
        projector: project_content_message,
    },
    FactRoute {
        tag: content_message_deletion::layout::TYPE_CONTENT_MESSAGE_DELETION,
        projector: project_content_message_deletion,
    },
    FactRoute {
        tag: content_reaction::layout::TYPE_CONTENT_REACTION,
        projector: project_content_reaction,
    },
    FactRoute {
        tag: encryption::layout::TYPE_RECIPIENT_KEY,
        projector: project_encryption,
    },
    FactRoute {
        tag: encryption::layout::TYPE_REMOVAL_FRONTIER,
        projector: project_encryption,
    },
    FactRoute {
        tag: encryption::layout::TYPE_LOCAL_KEY_SECRET,
        projector: project_encryption,
    },
    FactRoute {
        tag: encryption::layout::TYPE_LOCAL_HISTORY_NODE_SECRET,
        projector: project_encryption,
    },
    FactRoute {
        tag: encryption::layout::TYPE_KEY_REQUEST,
        projector: project_encryption,
    },
    FactRoute {
        tag: encryption::layout::TYPE_KEY_WRAP,
        projector: project_encryption,
    },
    FactRoute {
        tag: encryption::layout::TYPE_LOCAL_RECIPIENT_KEY,
        projector: project_encryption,
    },
    FactRoute {
        tag: identity_endpoint::layout::TYPE_LOCAL_ENDPOINT,
        projector: project_endpoint,
    },
    FactRoute {
        tag: identity_invite::layout::TYPE_INVITE_SECRET,
        projector: project_invite,
    },
    FactRoute {
        tag: identity_workspace::layout::TYPE_WORKSPACE,
        projector: project_workspace,
    },
    FactRoute {
        tag: signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET,
        projector: project_signed_fact,
    },
    FactRoute {
        tag: identity_device_invite::layout::TYPE_DEVICE_INVITE,
        projector: project_device_invite,
    },
    FactRoute {
        tag: identity_endpoint_shared::layout::TYPE_ENDPOINT_SHARED,
        projector: project_endpoint_shared,
    },
    FactRoute {
        tag: identity_invite_server::layout::TYPE_INVITE_SERVER,
        projector: project_invite_server,
    },
    FactRoute {
        tag: identity_admin::layout::TYPE_ADMIN,
        projector: project_admin,
    },
    FactRoute {
        tag: sealed_message::layout::TYPE_SEALED_MESSAGE,
        projector: project_sealed_message,
    },
    FactRoute {
        tag: sealed_message::layout::TYPE_SIGNER_PUBKEY,
        projector: project_sealed_message,
    },
    FactRoute {
        tag: sealed_message::layout::TYPE_SECRET_NODE,
        projector: project_sealed_message,
    },
    FactRoute {
        tag: sealed_message::layout::TYPE_MESSAGE_DELETION,
        projector: project_sealed_message,
    },
    FactRoute {
        tag: identity_invite_accepted::layout::TYPE_INVITE_ACCEPTED,
        projector: project_invite_accepted,
    },
    FactRoute {
        tag: disappearing_messages_setting::layout::TYPE_DISAPPEARING_MESSAGES_SETTING,
        projector: project_disappearing_messages_setting,
    },
    FactRoute {
        tag: sync_range_request::layout::TYPE_SYNC_RANGE_REQUEST,
        projector: project_sync_range_request,
    },
    FactRoute {
        tag: sync_encrypted_root::layout::TYPE_ENCRYPTED_ROOT,
        projector: project_sync_encrypted_root,
    },
    FactRoute {
        tag: sync_shared_event::layout::TYPE_SHARED_EVENT,
        projector: project_sync_shared_event,
    },
    FactRoute {
        tag: sync_key_wrap_available::layout::TYPE_KEY_WRAP_AVAILABLE,
        projector: project_sync_key_wrap_available,
    },
    FactRoute {
        tag: sync_compare::layout::TYPE_SYNC_COMPARE,
        projector: project_sync_compare,
    },
    FactRoute {
        tag: sync_have_id::layout::TYPE_SYNC_HAVE_ID,
        projector: project_sync_have_id,
    },
    FactRoute {
        tag: sync_need_id::layout::TYPE_SYNC_NEED_ID,
        projector: project_sync_need_id,
    },
    FactRoute {
        tag: transit_received::layout::TYPE_TRANSIT_RECEIVED,
        projector: project_transit_received,
    },
    FactRoute {
        tag: identity_user_invite::layout::TYPE_USER_INVITE,
        projector: project_user_invite,
    },
    FactRoute {
        tag: identity_user::layout::TYPE_USER,
        projector: project_user,
    },
    FactRoute {
        tag: local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET,
        projector: project_local_history_node_secret,
    },
    FactRoute {
        tag: removal_frontier::layout::TYPE_REMOVAL_FRONTIER,
        projector: project_removal_frontier,
    },
];

pub struct ProtocolContextMatchers {
    matchers: Vec<Box<dyn ContextMatcher>>,
}

impl ProtocolContextMatchers {
    fn new() -> Self {
        let mut exact_roles = std::collections::BTreeSet::<Role>::new();
        let mut custom_matcher_names = std::collections::BTreeSet::<&'static str>::new();
        for registration in super::CONTEXT_MATCHERS {
            match registration.matcher {
                "ExactSelectorMatcher" => {
                    exact_roles.insert(
                        Role::new(registration.role).expect("registered exact matcher role"),
                    );
                }
                "RangeEventMatcher" | "SecretCoverageMatcher" | "WrapSourceMatcher" => {
                    custom_matcher_names.insert(registration.matcher);
                }
                other => panic!("unknown context matcher {other}"),
            }
        }

        let mut matchers: Vec<Box<dyn ContextMatcher>> =
            exact_roles.into_iter().map(exact_matcher).collect();
        for matcher in custom_matcher_names {
            match matcher {
                "RangeEventMatcher" => {
                    matchers.push(Box::new(sync::matchers::RangeEventMatcher::new()))
                }
                "SecretCoverageMatcher" => matchers.push(Box::new(
                    sealed_message::matchers::SecretCoverageMatcher::new(),
                )),
                "WrapSourceMatcher" => {
                    matchers.push(Box::new(encryption::matchers::WrapSourceMatcher::new()))
                }
                other => panic!("unknown context matcher {other}"),
            }
        }
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

const HANDLER_ROUTES: &[HandlerRoute] = &[
    HandlerRoute {
        name: "bootstrap_send",
        factory: || Box::new(bootstrap_send::BootstrapSendRequestHandler::new()),
    },
    HandlerRoute {
        name: "connection_response",
        factory: || Box::new(connection_response_handler::ConnectionResponseHandler::new()),
    },
    HandlerRoute {
        name: "handle_sync",
        factory: || Box::new(handle_sync::HandleSyncHandler::new()),
    },
    HandlerRoute {
        name: "respond_to_sync_compare",
        factory: || Box::new(handle_sync::RespondToSyncCompareHandler::new()),
    },
    HandlerRoute {
        name: "request_sync_id",
        factory: || Box::new(handle_sync::RequestSyncIdHandler::new()),
    },
    HandlerRoute {
        name: "respond_to_sync_need",
        factory: || Box::new(handle_sync::RespondToSyncNeedHandler::new()),
    },
    HandlerRoute {
        name: "seed_sync_connection",
        factory: || Box::new(handle_sync::SeedSyncConnectionHandler::new()),
    },
    HandlerRoute {
        name: "materialize_key_wraps",
        factory: || Box::new(materialize_key_wraps::MaterializeKeyWrapsHandler::new()),
    },
    HandlerRoute {
        name: "purge_cascade",
        factory: || Box::new(purge_cascade::PurgeCascadeHandler::new()),
    },
    HandlerRoute {
        name: "purge_event",
        factory: || Box::new(purge_event::PurgeEventHandler::new()),
    },
    HandlerRoute {
        name: "purge_retired_recipient_material",
        factory: || {
            Box::new(purge_retired_recipient_material::PurgeRetiredRecipientMaterialHandler::new())
        },
    },
    HandlerRoute {
        name: "receive_transit",
        factory: || Box::new(receive_transit::ReceiveTransitHandler::new()),
    },
    HandlerRoute {
        name: "retention_expiry",
        factory: || Box::new(retention_expiry::RetentionExpiryHandler::new()),
    },
    HandlerRoute {
        name: "retention_floor",
        factory: || Box::new(retention_floor::RetentionFloorHandler::new()),
    },
    HandlerRoute {
        name: "sync_index_update",
        factory: || Box::new(sync_index_update::SyncIndexUpdateHandler::new()),
    },
    HandlerRoute {
        name: "transit",
        factory: || Box::new(transit::TransitSendOnConnectionHandler::new()),
    },
    HandlerRoute {
        name: "network_send",
        factory: || Box::new(network_send::NetworkSendHandler::new()),
    },
    HandlerRoute {
        name: "unwrap_key_wrap",
        factory: || Box::new(unwrap_key_wrap::UnwrapKeyWrapHandler::new()),
    },
];

pub fn protocol_handler_route_names() -> impl Iterator<Item = &'static str> {
    HANDLER_ROUTES.iter().map(|route| route.name)
}
