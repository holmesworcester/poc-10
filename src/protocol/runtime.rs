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
use crate::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE, INTENTS_SCHEMA_SOURCE};
use crate::core::store::{Schema, TableName};
use crate::core::tcp;
use crate::core::wake_loop::DispatchReport;
use crate::protocol::facts::{connection, content, encryption, identity, sync, transport};
use crate::protocol::intents::{
    connection as connection_intents, content as content_intents, encryption as encryption_intents,
    sync as sync_intents, transport as transport_intents,
};
use std::collections::BTreeSet;

pub type ProtocolRuntime = crate::core::runtime::Runtime<super::Protocol>;

impl crate::core::runtime::Runtime<super::Protocol> {
    pub fn dispatch_cli_intents(
        &mut self,
        limit_per_handler: usize,
    ) -> Result<DispatchReport, String> {
        let handlers = HandlerSet::new_excluding(HANDLER_ROUTES, CLI_EFFECT_HANDLER_ROUTES);
        self.dispatch_with_handlers(&handlers, limit_per_handler)
    }

    pub fn daemon_tick(
        &mut self,
        listener: &tcp::Listener,
        work_limit: usize,
    ) -> Result<TickReport, String> {
        self.reload_wake_loop_if_store_changed()?;
        let accepted = listener.accept_available(self.store(), work_limit)?;
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

        if let Some(current_minute) = current_minute(self.store())? {
            self.wake_time_range(
                content::sealed_message::expiration_timeline(),
                None,
                current_minute,
                work_limit,
            );
        }
        let projection_before_handlers = self.drain_projection_until_idle(4, work_limit)?;
        let dispatched = self.dispatch_intents(work_limit)?;
        let projection_after_handlers = self.drain_projection_until_idle(4, work_limit)?;
        self.save()?;
        if dispatched.retries == 0 {
            network_queues::delete_inbound(self.store(), &inbound)?;
        }

        Ok(TickReport {
            accepted_connections: accepted.accepted_connections,
            sent_frames: accepted.value.sent_frames,
            received_frames: accepted.value.received_frames,
            projections: projection_before_handlers.projections
                + projection_after_handlers.projections,
            handled_intents: dispatched.handled,
            emitted_facts: dispatched.facts,
            emitted_intents: dispatched.intents,
        })
    }
}

const CLI_EFFECT_HANDLER_ROUTES: &[&str] = &[
    "send_facts_on_connection",
    "send_network_frame",
    "receive_transit_frame",
];

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn current_minute(store: &crate::core::store::Store) -> Result<Option<u64>, String> {
    Ok(logical_clock::logical_time(store)?.map(|now_ms| now_ms / 60_000))
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
    type Handlers = HandlerSet;

    fn schema_sources() -> &'static [&'static str] {
        SCHEMA_SOURCES
    }

    fn schemas() -> &'static [Schema] {
        network_queues::SCHEMAS
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
        RouterProjector::new(FACT_ROUTES, ENVELOPE_ROUTES).project(fact, context)
    }
}

macro_rules! projector_route {
    ($name:ident, $projector:path) => {
        fn $name(fact: &Fact, context: &ProjectionContext) -> Result<ProjectionOutput, String> {
            <$projector>::new().project(fact, context)
        }
    };
}

projector_route!(
    project_cascade_fact,
    sync::cascade_fact::project::CascadeFactProjector
);
projector_route!(
    project_connection_ephemeral_secret,
    connection::ephemeral_secret::project::ConnectionEphemeralSecretProjector
);
projector_route!(
    project_connection_request,
    connection::request::project::ConnectionRequestProjector
);
projector_route!(
    project_connection_response,
    connection::response::project::ConnectionResponseProjector
);
projector_route!(
    project_content_event,
    content::event::project::ContentEventProjector
);
projector_route!(
    project_content_file,
    content::file::project::ContentFileProjector
);
projector_route!(
    project_content_file_deletion,
    content::file_deletion::project::ContentFileDeletionProjector
);
projector_route!(
    project_content_file_slice,
    content::file_slice::project::ContentFileSliceProjector
);
projector_route!(
    project_content_reaction,
    content::reaction::project::ContentReactionProjector
);
projector_route!(project_encryption, encryption::project::EncryptionProjector);
projector_route!(
    project_endpoint,
    identity::endpoint::project::EndpointProjector
);
projector_route!(
    project_invite,
    identity::invite::project::InviteSecretProjector
);
projector_route!(
    project_workspace,
    identity::workspace::project::WorkspaceProjector
);
projector_route!(
    project_signed_fact,
    identity::signed_fact::project::SignedFactProjector
);
projector_route!(
    project_device_invite,
    identity::device_invite::project::DeviceInviteProjector
);
projector_route!(
    project_endpoint_shared,
    identity::endpoint_shared::project::EndpointSharedProjector
);
projector_route!(
    project_invite_server,
    identity::invite_server::project::InviteServerProjector
);
projector_route!(project_admin, identity::admin::project::AdminProjector);
projector_route!(
    project_sealed_message,
    content::sealed_message::project::SealedMessageProjector
);
projector_route!(
    project_invite_accepted,
    identity::invite_accepted::project::InviteAcceptedProjector
);
projector_route!(
    project_disappearing_messages_setting,
    encryption::disappearing_messages_setting::project::DisappearingMessagesSettingProjector
);
projector_route!(
    project_sync_range_request,
    sync::range_request::project::SyncRangeRequestProjector
);
projector_route!(
    project_sync_encrypted_root,
    sync::encrypted_root::project::SyncEncryptedRootProjector
);
projector_route!(
    project_sync_shared_fact,
    sync::shared_fact::project::SyncSharedFactProjector
);
projector_route!(
    project_sync_key_wrap_available,
    sync::key_wrap_available::project::SyncKeyWrapAvailableProjector
);
projector_route!(
    project_sync_compare,
    sync::compare::project::SyncCompareProjector
);
projector_route!(
    project_sync_have_id,
    sync::have_id::project::SyncHaveIdProjector
);
projector_route!(
    project_sync_need_id,
    sync::need_id::project::SyncNeedIdProjector
);
projector_route!(
    project_transit_received,
    transport::transit_received::project::TransitReceivedProjector
);
projector_route!(
    project_user_invite,
    identity::user_invite::project::UserInviteProjector
);
projector_route!(project_user, identity::user::project::UserProjector);
projector_route!(
    project_local_history_node_secret,
    encryption::local_history_node_secret::project::LocalHistoryNodeSecretProjector
);
projector_route!(
    project_removal_frontier,
    encryption::removal_frontier::project::RemovalFrontierProjector
);

fn signed_effective_tag(fact: &Fact) -> Result<u8, String> {
    Ok(identity::signed_fact::layout::decode_signed_fact(&fact.bytes)?.inner_type)
}

const ENVELOPE_ROUTES: &[EnvelopeRoute] = &[EnvelopeRoute {
    outer_tag: identity::signed_fact::layout::TYPE_SIGNED_FACT,
    effective_tag: signed_effective_tag,
}];

const FACT_ROUTES: &[FactRoute] = &[
    FactRoute {
        tag: sync::cascade_fact::layout::TYPE_CASCADE_FACT,
        projector: project_cascade_fact,
    },
    FactRoute {
        tag: connection::ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET,
        projector: project_connection_ephemeral_secret,
    },
    FactRoute {
        tag: connection::request::layout::TYPE_CONNECTION_REQUEST,
        projector: project_connection_request,
    },
    FactRoute {
        tag: connection::response::layout::TYPE_CONNECTION_RESPONSE,
        projector: project_connection_response,
    },
    FactRoute {
        tag: content::event::layout::TYPE_CONTENT_EVENT,
        projector: project_content_event,
    },
    FactRoute {
        tag: content::file::layout::TYPE_CONTENT_FILE,
        projector: project_content_file,
    },
    FactRoute {
        tag: content::file_deletion::layout::TYPE_CONTENT_FILE_DELETION,
        projector: project_content_file_deletion,
    },
    FactRoute {
        tag: content::file_slice::layout::TYPE_CONTENT_FILE_SLICE,
        projector: project_content_file_slice,
    },
    FactRoute {
        tag: content::reaction::layout::TYPE_CONTENT_REACTION,
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
        tag: identity::endpoint::layout::TYPE_LOCAL_ENDPOINT,
        projector: project_endpoint,
    },
    FactRoute {
        tag: identity::invite::layout::TYPE_INVITE_SECRET,
        projector: project_invite,
    },
    FactRoute {
        tag: identity::workspace::layout::TYPE_WORKSPACE,
        projector: project_workspace,
    },
    FactRoute {
        tag: identity::signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET,
        projector: project_signed_fact,
    },
    FactRoute {
        tag: identity::device_invite::layout::TYPE_DEVICE_INVITE,
        projector: project_device_invite,
    },
    FactRoute {
        tag: identity::endpoint_shared::layout::TYPE_ENDPOINT_SHARED,
        projector: project_endpoint_shared,
    },
    FactRoute {
        tag: identity::invite_server::layout::TYPE_INVITE_SERVER,
        projector: project_invite_server,
    },
    FactRoute {
        tag: identity::admin::layout::TYPE_ADMIN,
        projector: project_admin,
    },
    FactRoute {
        tag: content::sealed_message::layout::TYPE_SEALED_MESSAGE,
        projector: project_sealed_message,
    },
    FactRoute {
        tag: content::sealed_message::layout::TYPE_SIGNER_PUBKEY,
        projector: project_sealed_message,
    },
    FactRoute {
        tag: content::sealed_message::layout::TYPE_SECRET_NODE,
        projector: project_sealed_message,
    },
    FactRoute {
        tag: content::sealed_message::layout::TYPE_MESSAGE_DELETION,
        projector: project_sealed_message,
    },
    FactRoute {
        tag: identity::invite_accepted::layout::TYPE_INVITE_ACCEPTED,
        projector: project_invite_accepted,
    },
    FactRoute {
        tag: encryption::disappearing_messages_setting::layout::TYPE_DISAPPEARING_MESSAGES_SETTING,
        projector: project_disappearing_messages_setting,
    },
    FactRoute {
        tag: sync::range_request::layout::TYPE_SYNC_RANGE_REQUEST,
        projector: project_sync_range_request,
    },
    FactRoute {
        tag: sync::encrypted_root::layout::TYPE_ENCRYPTED_ROOT,
        projector: project_sync_encrypted_root,
    },
    FactRoute {
        tag: sync::shared_fact::layout::TYPE_SHARED_FACT,
        projector: project_sync_shared_fact,
    },
    FactRoute {
        tag: sync::key_wrap_available::layout::TYPE_KEY_WRAP_AVAILABLE,
        projector: project_sync_key_wrap_available,
    },
    FactRoute {
        tag: sync::compare::layout::TYPE_SYNC_COMPARE,
        projector: project_sync_compare,
    },
    FactRoute {
        tag: sync::have_id::layout::TYPE_SYNC_HAVE_ID,
        projector: project_sync_have_id,
    },
    FactRoute {
        tag: sync::need_id::layout::TYPE_SYNC_NEED_ID,
        projector: project_sync_need_id,
    },
    FactRoute {
        tag: transport::transit_received::layout::TYPE_TRANSIT_RECEIVED,
        projector: project_transit_received,
    },
    FactRoute {
        tag: identity::user_invite::layout::TYPE_USER_INVITE,
        projector: project_user_invite,
    },
    FactRoute {
        tag: identity::user::layout::TYPE_USER,
        projector: project_user,
    },
    FactRoute {
        tag: encryption::local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET,
        projector: project_local_history_node_secret,
    },
    FactRoute {
        tag: encryption::removal_frontier::layout::TYPE_REMOVAL_FRONTIER,
        projector: project_removal_frontier,
    },
];

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

const HANDLER_ROUTES: &[HandlerRoute] = &[
    HandlerRoute {
        name: "send_bootstrap_connection_request",
        factory: || {
            Box::new(
                connection_intents::send_bootstrap_request::SendBootstrapConnectionRequestHandler::new(),
            )
        },
    },
    HandlerRoute {
        name: "create_connection_response",
        factory: || {
            Box::new(connection_intents::create_response::CreateConnectionResponseHandler::new())
        },
    },
    HandlerRoute {
        name: "send_sync_compare_response",
        factory: || {
            Box::new(sync_intents::send_compare_response::SendSyncCompareResponseHandler::new())
        },
    },
    HandlerRoute {
        name: "send_needed_fact_id",
        factory: || Box::new(sync_intents::send_needed_fact_id::SendNeededFactIdHandler::new()),
    },
    HandlerRoute {
        name: "send_requested_fact",
        factory: || Box::new(sync_intents::send_requested_fact::SendRequestedFactHandler::new()),
    },
    HandlerRoute {
        name: "share_fact_with_workspace",
        factory: || {
            Box::new(sync_intents::share_fact_with_workspace::ShareFactWithWorkspaceHandler::new())
        },
    },
    HandlerRoute {
        name: "seed_connection_sync",
        factory: || Box::new(sync_intents::seed_connection::SeedConnectionSyncHandler::new()),
    },
    HandlerRoute {
        name: "create_key_wrap",
        factory: || Box::new(encryption_intents::create_key_wrap::CreateKeyWrapHandler::new()),
    },
    HandlerRoute {
        name: "purge_retired_recipient_material",
        factory: || {
            Box::new(
                encryption_intents::purge_retired_recipient_material::PurgeRetiredRecipientMaterialHandler::new(),
            )
        },
    },
    HandlerRoute {
        name: "unwrap_key_wrap",
        factory: || Box::new(encryption_intents::unwrap_key_wrap::UnwrapKeyWrapHandler::new()),
    },
    HandlerRoute {
        name: "purge_deleted_message",
        factory: || {
            Box::new(content_intents::purge_deleted_message::PurgeDeletedMessageHandler::new())
        },
    },
    HandlerRoute {
        name: "purge_message_child",
        factory: || Box::new(content_intents::purge_message_child::PurgeMessageChildHandler::new()),
    },
    HandlerRoute {
        name: "purge_expired_message",
        factory: || {
            Box::new(content_intents::purge_expired_message::PurgeExpiredMessageHandler::new())
        },
    },
    HandlerRoute {
        name: "purge_below_retention_floor",
        factory: || {
            Box::new(
                content_intents::purge_below_retention_floor::PurgeBelowRetentionFloorHandler::new(
                ),
            )
        },
    },
    HandlerRoute {
        name: "send_facts_on_connection",
        factory: || {
            Box::new(
                transport_intents::send_facts_on_connection::SendFactsOnConnectionHandler::new(),
            )
        },
    },
    HandlerRoute {
        name: "send_network_frame",
        factory: || Box::new(transport_intents::send_network_frame::SendNetworkFrameHandler::new()),
    },
    HandlerRoute {
        name: "receive_transit_frame",
        factory: || {
            Box::new(transport_intents::receive_transit_frame::ReceiveTransitFrameHandler::new())
        },
    },
];

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
