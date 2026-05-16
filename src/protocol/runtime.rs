//! Runtime bindings for the concrete `match` protocol.
//!
//! Core owns the runtime mechanics. This module supplies the protocol-specific
//! projector router, matcher set, handler set, schema sources, and atomic row
//! tables needed by `core::runtime::Runtime<Protocol>`.

use crate::core::context::Role;
use crate::core::daemon::TickReport;
use crate::core::facts::{Fact, FactScope};
use crate::core::handler_dispatch::HandlerContext;
use crate::core::logical_clock;
use crate::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use crate::core::network_queues;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::core::runtime::{RuntimeHandlers, RuntimeMatchers, RuntimeProtocol};
use crate::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE, INTENTS_SCHEMA_SOURCE};
use crate::core::store::Store;
use crate::core::store::TableName;
use crate::core::tcp;
use crate::core::wake_loop::{DispatchReport, WakeLoop};
use crate::protocol::facts::{connection, content, encryption, identity, sync, transport};
use crate::protocol::intents::{
    connection as connection_intents, content as content_intents, encryption as encryption_intents,
    sync as sync_intents, transport as transport_intents,
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
            self.submit_intent(
                transport_intents::receive_transit_frame::receive_transit_frame_intent(
                    transport_intents::receive_transit_frame::ReceiveTransitFrame {
                        frame: row.bytes.clone(),
                        origin_addr: transport::transit_received::addr::canonical_origin_addr_bytes(
                            row.source.addr(),
                        ),
                        received_at_local_ms: now_ms(),
                    },
                )?,
            )?;
        }
        network_queues::delete_inbound(self.store(), &inbound)?;

        let projection_before_handlers = self.drain_projection_until_idle(4, work_limit)?;
        let queued_retention = self.enqueue_due_retention(work_limit)?;
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
            emitted_intents: dispatched.intents + dispatched_after_seed.intents + queued_retention,
        })
    }

    pub fn enqueue_due_retention(&mut self, limit: usize) -> Result<usize, String> {
        let Some(now_ms) = logical_clock::logical_time(self.store())? else {
            return Ok(0);
        };
        let now_minute = now_ms / 60_000;
        let sealed_rows = self
            .store()
            .table_rows(content::sealed_message::rows::SEALED_MESSAGE_ROWS)
            .map_err(|err| format!("load sealed message rows for retention: {err}"))?
            .into_iter()
            .map(|(key, value)| {
                content::sealed_message::rows::decode_sealed_message_row(&key, &value)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut queued = 0usize;
        for row in sealed_rows {
            if queued >= limit {
                break;
            }
            if row.expires_at_minute != u64::MAX && row.expires_at_minute <= now_minute {
                if self.submit_intent(
                    content_intents::purge_expired_message::purge_expired_message_intent(
                        content_intents::purge_expired_message::PurgeExpiredMessage {
                            workspace_id: row.workspace_id,
                            target_id: row.message_id,
                            now_minute,
                        },
                    ),
                )? {
                    queued += 1;
                }
                continue;
            }
            let Some(active) =
                encryption::disappearing_messages_setting::queries::active_for_workspace(
                    self.store(),
                    row.workspace_id,
                )?
                .filter(|setting| row.minute < setting.retire_minute)
            else {
                continue;
            };
            if self.submit_intent(
                content_intents::purge_below_retention_floor::purge_below_retention_floor_intent(
                    content_intents::purge_below_retention_floor::PurgeBelowRetentionFloor {
                        workspace_id: row.workspace_id,
                        setting_id: active.setting_id,
                        target_id: row.message_id,
                    },
                ),
            )? {
                queued += 1;
            }
        }
        Ok(queued)
    }

    fn seed_sync_have_ids(&mut self, limit: usize) -> Result<usize, String> {
        let mut seeded = 0usize;
        let connections = self
            .store()
            .table_rows(connection::response::rows::CONNECTION_RESPONSE_ROWS)
            .map_err(|err| format!("load connection rows for sync seed: {err}"))?;
        if connections.is_empty() {
            return Ok(0);
        }
        for (connection_key, connection_value) in connections {
            let row = connection::response::rows::decode_connection_response_row(
                &connection_key,
                &connection_value,
            )?;
            let facts =
                sync::shared_fact::shareable_facts_for_connection(self.store(), row.connection_id)?;
            for fact in facts {
                if seeded >= limit {
                    return Ok(seeded);
                }
                let have = sync::have_id::fact::SyncHaveIdFact {
                    connection_id: row.connection_id,
                    timestamp: fact.timestamp,
                    fact_id: fact.id,
                };
                let have_fact = Fact::new(
                    FactScope::Global,
                    fact.timestamp,
                    sync::have_id::layout::encode_fact(&have)?,
                );
                if self.submit_fact(have_fact.clone()) {
                    self.submit_intent(transport_intents::send_facts_on_connection::send_facts_on_connection_intent(
                        transport_intents::send_facts_on_connection::SendFactsOnConnection {
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

const SCHEMA_SOURCES: &[&str] = &[
    CORE_SCHEMA_SOURCE,
    FACTS_SCHEMA_SOURCE,
    INTENTS_SCHEMA_SOURCE,
];

const ATOMIC_ROW_TABLES: &[TableName] = &[
    sync::cascade_fact::rows::CASCADE_STAGED_FACT_ROWS,
    connection::ephemeral_secret::rows::CONNECTION_EPHEMERAL_SECRET_ROWS,
    connection::request::rows::CONNECTION_REQUEST_ROWS,
    connection::response::rows::CONNECTION_RESPONSE_ROWS,
    content::event::rows::CONTENT_EVENT_ROWS,
    content::file::rows::FILE_ROWS,
    content::file_deletion::rows::FILE_DELETION_ROWS,
    content::file_slice::rows::FILE_SLICE_ROWS,
    content::reaction::rows::REACTION_ROWS,
    encryption::disappearing_messages_setting::rows::DISAPPEARING_MESSAGES_SETTING_ROWS,
    encryption::rows::KEY_WRAP_ROWS,
    identity::admin::rows::ADMIN_ROWS,
    identity::device_invite::rows::DEVICE_INVITE_ROWS,
    identity::endpoint::rows::LOCAL_ENDPOINT_ROWS,
    identity::endpoint::rows::LOCAL_ENDPOINT_SECRET_ROWS,
    identity::endpoint::rows::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
    identity::endpoint::rows::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS,
    identity::endpoint_shared::rows::ENDPOINT_SHARED_ROWS,
    identity::invite::rows::INVITE_SECRET_ROWS,
    identity::invite_accepted::rows::INVITE_ACCEPTED_ROWS,
    identity::invite_server::rows::INVITE_SERVER_ROWS,
    identity::user::rows::USER_ROWS,
    identity::user_invite::rows::USER_INVITE_ROWS,
    identity::workspace::rows::WORKSPACE_ROWS,
    encryption::local_history_node_secret::rows::LOCAL_HISTORY_NODE_SECRET_ROWS,
    encryption::removal_frontier::rows::REMOVAL_FRONTIER_ROWS,
    content::sealed_message::rows::MESSAGE_ROWS,
    content::sealed_message::rows::OPENED_MESSAGE_ROWS,
    content::sealed_message::rows::MESSAGE_TOMBSTONE_ROWS,
    content::sealed_message::rows::SEALED_MESSAGE_ROWS,
    sync::compare::rows::SYNC_COMPARE_ROWS,
    sync::have_id::rows::SYNC_HAVE_ID_ROWS,
    sync::need_id::rows::SYNC_NEED_ID_ROWS,
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
            sync::cascade_fact::layout::TYPE_CASCADE_FACT => {
                sync::cascade_fact::project::CascadeFactProjector::new().project(fact, context)
            }
            connection::ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET => {
                connection::ephemeral_secret::project::ConnectionEphemeralSecretProjector::new()
                    .project(fact, context)
            }
            connection::request::layout::TYPE_CONNECTION_REQUEST => {
                connection::request::project::ConnectionRequestProjector::new()
                    .project(fact, context)
            }
            connection::response::layout::TYPE_CONNECTION_RESPONSE => {
                connection::response::project::ConnectionResponseProjector::new()
                    .project(fact, context)
            }
            content::event::layout::TYPE_CONTENT_EVENT => {
                content::event::project::ContentEventProjector::new().project(fact, context)
            }
            content::file::layout::TYPE_CONTENT_FILE => {
                content::file::project::ContentFileProjector::new().project(fact, context)
            }
            content::file_deletion::layout::TYPE_CONTENT_FILE_DELETION => {
                content::file_deletion::project::ContentFileDeletionProjector::new()
                    .project(fact, context)
            }
            content::file_slice::layout::TYPE_CONTENT_FILE_SLICE => {
                content::file_slice::project::ContentFileSliceProjector::new().project(fact, context)
            }
            content::reaction::layout::TYPE_CONTENT_REACTION => {
                content::reaction::project::ContentReactionProjector::new().project(fact, context)
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
            identity::endpoint::layout::TYPE_LOCAL_ENDPOINT => {
                identity::endpoint::project::EndpointProjector::new().project(fact, context)
            }
            identity::invite::layout::TYPE_INVITE_SECRET => {
                identity::invite::project::InviteSecretProjector::new().project(fact, context)
            }
            identity::workspace::layout::TYPE_WORKSPACE => {
                identity::workspace::project::WorkspaceProjector::new().project(fact, context)
            }
            identity::signed_fact::layout::TYPE_SIGNED_FACT => {
                let envelope = identity::signed_fact::layout::decode_signed_fact(&fact.bytes)?;
                match envelope.inner_type {
                    identity::user_invite::layout::TYPE_USER_INVITE => {
                        identity::user_invite::project::UserInviteProjector::new()
                            .project(fact, context)
                    }
                    identity::user::layout::TYPE_USER => {
                        identity::user::project::UserProjector::new().project(fact, context)
                    }
                    identity::admin::layout::TYPE_ADMIN => {
                        identity::admin::project::AdminProjector::new().project(fact, context)
                    }
                    identity::endpoint_shared::layout::TYPE_ENDPOINT_SHARED => {
                        identity::endpoint_shared::project::EndpointSharedProjector::new()
                            .project(fact, context)
                    }
                    identity::device_invite::layout::TYPE_DEVICE_INVITE => {
                        identity::device_invite::project::DeviceInviteProjector::new()
                            .project(fact, context)
                    }
                    identity::invite_server::layout::TYPE_INVITE_SERVER => {
                        identity::invite_server::project::InviteServerProjector::new()
                            .project(fact, context)
                    }
                    encryption::layout::TYPE_KEY_WRAP => {
                        encryption::project::EncryptionProjector::new().project(fact, context)
                    }
                    content::sealed_message::layout::TYPE_SEALED_MESSAGE => {
                        content::sealed_message::project::SealedMessageProjector::new()
                            .project(fact, context)
                    }
                    inner_type => Err(format!(
                        "no target projector registered for signed inner fact tag {inner_type}"
                    )),
                }
            }
            identity::signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET => {
                identity::signed_fact::project::SignedFactProjector::new().project(fact, context)
            }
            identity::device_invite::layout::TYPE_DEVICE_INVITE => {
                identity::device_invite::project::DeviceInviteProjector::new().project(fact, context)
            }
            identity::endpoint_shared::layout::TYPE_ENDPOINT_SHARED => {
                identity::endpoint_shared::project::EndpointSharedProjector::new()
                    .project(fact, context)
            }
            identity::invite_server::layout::TYPE_INVITE_SERVER => {
                identity::invite_server::project::InviteServerProjector::new().project(fact, context)
            }
            identity::admin::layout::TYPE_ADMIN => {
                identity::admin::project::AdminProjector::new().project(fact, context)
            }
            content::sealed_message::layout::TYPE_SEALED_MESSAGE
            | content::sealed_message::layout::TYPE_SIGNER_PUBKEY
            | content::sealed_message::layout::TYPE_SECRET_NODE => {
                content::sealed_message::project::SealedMessageProjector::new().project(fact, context)
            }
            content::sealed_message::layout::TYPE_MESSAGE_DELETION => {
                content::sealed_message::project::SealedMessageProjector::new().project(fact, context)
            }
            identity::invite_accepted::layout::TYPE_INVITE_ACCEPTED => {
                identity::invite_accepted::project::InviteAcceptedProjector::new()
                    .project(fact, context)
            }
            encryption::disappearing_messages_setting::layout::TYPE_DISAPPEARING_MESSAGES_SETTING => {
                encryption::disappearing_messages_setting::project::DisappearingMessagesSettingProjector::new()
                    .project(fact, context)
            }
            sync::range_request::layout::TYPE_SYNC_RANGE_REQUEST => {
                sync::range_request::project::SyncRangeRequestProjector::new().project(fact, context)
            }
            sync::encrypted_root::layout::TYPE_ENCRYPTED_ROOT => {
                sync::encrypted_root::project::SyncEncryptedRootProjector::new()
                    .project(fact, context)
            }
            sync::shared_fact::layout::TYPE_SHARED_FACT => {
                sync::shared_fact::project::SyncSharedFactProjector::new().project(fact, context)
            }
            sync::key_wrap_available::layout::TYPE_KEY_WRAP_AVAILABLE => {
                sync::key_wrap_available::project::SyncKeyWrapAvailableProjector::new()
                    .project(fact, context)
            }
            sync::compare::layout::TYPE_SYNC_COMPARE => {
                sync::compare::project::SyncCompareProjector::new().project(fact, context)
            }
            sync::have_id::layout::TYPE_SYNC_HAVE_ID => {
                sync::have_id::project::SyncHaveIdProjector::new().project(fact, context)
            }
            sync::need_id::layout::TYPE_SYNC_NEED_ID => {
                sync::need_id::project::SyncNeedIdProjector::new().project(fact, context)
            }
            transport::transit_received::layout::TYPE_TRANSIT_RECEIVED => {
                transport::transit_received::project::TransitReceivedProjector::new().project(fact, context)
            }
            identity::user_invite::layout::TYPE_USER_INVITE => {
                identity::user_invite::project::UserInviteProjector::new().project(fact, context)
            }
            identity::user::layout::TYPE_USER => {
                identity::user::project::UserProjector::new().project(fact, context)
            }
            encryption::local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET => {
                encryption::local_history_node_secret::project::LocalHistoryNodeSecretProjector::new()
                    .project(fact, context)
            }
            encryption::removal_frontier::layout::TYPE_REMOVAL_FRONTIER => {
                encryption::removal_frontier::project::RemovalFrontierProjector::new().project(fact, context)
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
        let mut exact_roles = BTreeSet::<Role>::new();
        let mut custom_matcher_names = BTreeSet::<&'static str>::new();
        for registration in super::CONTEXT_MATCHERS {
            match registration.matcher {
                "ExactSelectorMatcher" => {
                    exact_roles.insert(
                        Role::new(registration.role).expect("registered exact matcher role"),
                    );
                }
                "RangeFactMatcher" | "SecretCoverageMatcher" | "WrapSourceMatcher" => {
                    custom_matcher_names.insert(registration.matcher);
                }
                other => panic!("unknown context matcher {other}"),
            }
        }

        let mut matchers: Vec<Box<dyn ContextMatcher>> =
            exact_roles.into_iter().map(exact_matcher).collect();
        for matcher in custom_matcher_names {
            match matcher {
                "RangeFactMatcher" => {
                    matchers.push(Box::new(super::matchers::RangeFactMatcher::new()));
                }
                "SecretCoverageMatcher" => {
                    matchers.push(Box::new(super::matchers::SecretCoverageMatcher::new()));
                }
                "WrapSourceMatcher" => {
                    matchers.push(Box::new(super::matchers::WrapSourceMatcher::new()));
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

#[derive(Debug, Clone)]
pub struct ProtocolHandlers {
    send_bootstrap_connection_request:
        connection_intents::send_bootstrap_request::SendBootstrapConnectionRequestHandler,
    create_connection_response:
        connection_intents::create_response::CreateConnectionResponseHandler,
    send_sync_compare_response: sync_intents::send_compare_response::SendSyncCompareResponseHandler,
    send_needed_fact_id: sync_intents::send_needed_fact_id::SendNeededFactIdHandler,
    send_requested_fact: sync_intents::send_requested_fact::SendRequestedFactHandler,
    share_fact_with_workspace:
        sync_intents::share_fact_with_workspace::ShareFactWithWorkspaceHandler,
    create_key_wrap: encryption_intents::create_key_wrap::CreateKeyWrapHandler,
    purge_retired_recipient_material:
        encryption_intents::purge_retired_recipient_material::PurgeRetiredRecipientMaterialHandler,
    unwrap_key_wrap: encryption_intents::unwrap_key_wrap::UnwrapKeyWrapHandler,
    purge_deleted_message: content_intents::purge_deleted_message::PurgeDeletedMessageHandler,
    purge_message_child: content_intents::purge_message_child::PurgeMessageChildHandler,
    purge_expired_message: content_intents::purge_expired_message::PurgeExpiredMessageHandler,
    purge_below_retention_floor:
        content_intents::purge_below_retention_floor::PurgeBelowRetentionFloorHandler,
    send_facts_on_connection:
        transport_intents::send_facts_on_connection::SendFactsOnConnectionHandler,
    send_network_frame: transport_intents::send_network_frame::SendNetworkFrameHandler,
    receive_transit_frame: transport_intents::receive_transit_frame::ReceiveTransitFrameHandler,
}

impl ProtocolHandlers {
    fn new() -> Self {
        Self {
            send_bootstrap_connection_request:
                connection_intents::send_bootstrap_request::SendBootstrapConnectionRequestHandler::new(),
            create_connection_response:
                connection_intents::create_response::CreateConnectionResponseHandler::new(),
            send_sync_compare_response:
                sync_intents::send_compare_response::SendSyncCompareResponseHandler::new(),
            send_needed_fact_id: sync_intents::send_needed_fact_id::SendNeededFactIdHandler::new(),
            send_requested_fact:
                sync_intents::send_requested_fact::SendRequestedFactHandler::new(),
            share_fact_with_workspace:
                sync_intents::share_fact_with_workspace::ShareFactWithWorkspaceHandler::new(),
            create_key_wrap: encryption_intents::create_key_wrap::CreateKeyWrapHandler::new(),
            purge_retired_recipient_material:
                encryption_intents::purge_retired_recipient_material::PurgeRetiredRecipientMaterialHandler::new(),
            unwrap_key_wrap: encryption_intents::unwrap_key_wrap::UnwrapKeyWrapHandler::new(),
            purge_deleted_message:
                content_intents::purge_deleted_message::PurgeDeletedMessageHandler::new(),
            purge_message_child:
                content_intents::purge_message_child::PurgeMessageChildHandler::new(),
            purge_expired_message:
                content_intents::purge_expired_message::PurgeExpiredMessageHandler::new(),
            purge_below_retention_floor:
                content_intents::purge_below_retention_floor::PurgeBelowRetentionFloorHandler::new(),
            send_facts_on_connection:
                transport_intents::send_facts_on_connection::SendFactsOnConnectionHandler::new(),
            send_network_frame:
                transport_intents::send_network_frame::SendNetworkFrameHandler::new(),
            receive_transit_frame:
                transport_intents::receive_transit_frame::ReceiveTransitFrameHandler::new(),
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
            &self.send_bootstrap_connection_request,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.create_connection_response,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.send_sync_compare_response,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.send_needed_fact_id,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.send_requested_fact,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.share_fact_with_workspace,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.create_key_wrap,
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
            &self.unwrap_key_wrap,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.purge_deleted_message,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.purge_message_child,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.purge_expired_message,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.purge_below_retention_floor,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.send_facts_on_connection,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.send_network_frame,
            store,
            limit_per_handler,
            &mut total,
        )?;
        self.dispatch_one(
            wake_loop,
            &self.receive_transit_frame,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::runtime::RuntimeProtocol;
    use crate::protocol::{Protocol, CONTEXT_MATCHERS};

    #[test]
    fn protocol_runtime_matchers_follow_registry_exact_roles() {
        let runtime_matchers = <Protocol as RuntimeProtocol>::matchers();
        let runtime_roles = runtime_matchers
            .matcher_refs()
            .into_iter()
            .filter_map(|matcher| {
                matcher
                    .exact_selector_role()
                    .map(|role| role.as_str().to_string())
            })
            .collect::<BTreeSet<_>>();
        let registry_roles = CONTEXT_MATCHERS
            .iter()
            .filter(|registration| registration.matcher == "ExactSelectorMatcher")
            .map(|registration| registration.role.to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(runtime_roles, registry_roles);
    }
}
