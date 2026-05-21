//! Declarative registry for the target protocol.
//!
//! This file names the commands, facts, context matchers, intents, handlers,
//! and schema sources that make up the poc-10 protocol. It is intentionally a
//! table of contents, not a runtime. `facts.rs` and `intents.rs` keep
//! concrete protocol namespaces visible; this registry says which of those
//! namespaces are part of the concrete protocol.

use crate::core::cli::CliCommand;
use crate::core::context::Role;
use crate::core::facts::Fact;
use crate::core::matchers::{
    ContextMatcher, ContextMatcherDeclaration, ContextRoleDeclaration, ExactSelectorMatcher,
};
use crate::core::network;
use crate::core::projectors::{
    EnvelopeRoute, FactRoute, ProjectionContext, ProjectionOutput, Projector, RouterProjector,
};
use crate::core::runtime::HandlerRoute;
use crate::core::schema::CORE_SCHEMA_SOURCE;
use crate::core::store::TableName;
use crate::protocol::facts::{connection, content, encryption, identity, sync, transport};
use crate::protocol::intents::{
    connection as connection_intents, content as content_intents, encryption as encryption_intents,
    sync as sync_intents, transport as transport_intents,
};
use crate::protocol::matchers;
use crate::protocol::{assertions, cli as command};
use std::collections::BTreeSet;

pub use crate::protocol::cli::MatchCliContext;

pub const FACTS_SCHEMA_SOURCE: &str = include_str!("facts/schema.p8sql");
pub const INTENTS_SCHEMA_SOURCE: &str = include_str!("intents/schema.p8sql");

#[derive(Clone, Copy)]
pub struct ProtocolRegistry {
    pub name: &'static str,
    pub schemas: &'static [SchemaRegistration],
    pub commands: &'static [CliCommand<MatchCliContext>],
    pub facts: &'static [FactRegistration],
    pub context_matchers: &'static [ContextRoleDeclaration],
    pub intents: &'static [IntentRegistration],
    pub handlers: &'static [HandlerRegistration],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaRegistration {
    pub name: &'static str,
    pub source: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactRegistration {
    pub module: &'static str,
    pub name: &'static str,
    pub tag: u8,
    pub projector: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentRegistration {
    pub kind: &'static str,
    pub queue: IntentQueueKind,
    pub declared_by: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentQueueKind {
    Durable,
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerRegistration {
    pub module: &'static str,
    pub handler: &'static str,
    pub runtime_field: &'static str,
    pub intents: &'static [&'static str],
}

pub const PROTOCOL: ProtocolRegistry = ProtocolRegistry {
    name: "match",
    schemas: SCHEMAS,
    commands: MATCH_COMMANDS,
    facts: FACTS,
    context_matchers: CONTEXT_MATCHERS,
    intents: INTENTS,
    handlers: HANDLERS,
};

macro_rules! cli_command {
    ($name:literal, $usage:path, $run:path) => {
        CliCommand {
            name: $name,
            usage: $usage,
            help: "",
            run: $run,
        }
    };
}

pub const MATCH_COMMANDS: &[CliCommand<MatchCliContext>] = &[
    cli_command!(
        "create-workspace",
        identity::workspace::cli::CREATE_WORKSPACE_USAGE,
        command::create_workspace
    ),
    cli_command!(
        "invite",
        identity::invite::cli::INVITE_USAGE,
        command::invite
    ),
    cli_command!(
        "invite-server",
        identity::invite::cli::INVITE_SERVER_USAGE,
        command::invite_server
    ),
    cli_command!(
        "accept",
        identity::invite::cli::ACCEPT_USAGE,
        command::accept
    ),
    cli_command!(
        "accept-invite-server",
        identity::invite::cli::ACCEPT_INVITE_SERVER_USAGE,
        command::accept_invite_server
    ),
    cli_command!("link", identity::invite::cli::LINK_USAGE, command::link),
    cli_command!(
        "accept-link",
        identity::invite::cli::ACCEPT_LINK_USAGE,
        command::accept_link
    ),
    cli_command!(
        "identity",
        identity::endpoint_shared::cli::IDENTITY_USAGE,
        command::identity
    ),
    cli_command!(
        "peers",
        identity::endpoint_shared::cli::PEERS_USAGE,
        command::peers
    ),
    cli_command!(
        "workspaces",
        identity::workspace::cli::WORKSPACES_USAGE,
        command::workspaces
    ),
    cli_command!("users", identity::user::cli::USERS_USAGE, command::users),
    cli_command!(
        "key-recipient",
        encryption::cli::KEY_RECIPIENT_USAGE,
        command::key_recipient
    ),
    cli_command!(
        "key-rotate-recipient",
        encryption::cli::KEY_ROTATE_RECIPIENT_USAGE,
        command::key_recipient_rotation
    ),
    cli_command!(
        "key-frontier",
        encryption::cli::KEY_FRONTIER_USAGE,
        command::key_frontier
    ),
    cli_command!(
        "key-wrap",
        encryption::cli::KEY_WRAP_USAGE,
        command::key_wrap
    ),
    cli_command!(
        "key-access",
        encryption::cli::KEY_ACCESS_USAGE,
        command::key_access
    ),
    cli_command!(
        "key-derive",
        encryption::cli::KEY_DERIVE_USAGE,
        command::key_derive
    ),
    cli_command!(
        "key-node",
        encryption::cli::KEY_NODE_USAGE,
        command::key_node
    ),
    cli_command!("keys", encryption::cli::KEYS_USAGE, command::keys),
    cli_command!(
        "chop-now",
        encryption::cli::CHOP_NOW_USAGE,
        command::chop_now
    ),
    cli_command!(
        "disappearing-set",
        encryption::disappearing_messages_setting::cli::DISAPPEARING_SET_USAGE,
        command::disappearing_set
    ),
    cli_command!(
        "disappearing-status",
        encryption::disappearing_messages_setting::cli::DISAPPEARING_STATUS_USAGE,
        command::disappearing_status
    ),
    cli_command!(
        "disappearing-tighten",
        encryption::disappearing_messages_setting::cli::DISAPPEARING_TIGHTEN_USAGE,
        command::disappearing_tighten
    ),
    cli_command!(
        "disappearing-compact",
        encryption::disappearing_messages_setting::cli::DISAPPEARING_COMPACT_USAGE,
        command::disappearing_compact
    ),
    cli_command!("send", content::message::cli::SEND_USAGE, command::send),
    cli_command!("react", content::message::cli::REACT_USAGE, command::react),
    cli_command!(
        "send-file",
        content::message::cli::SEND_FILE_USAGE,
        command::send_file
    ),
    cli_command!("files", content::message::cli::FILES_USAGE, command::files),
    cli_command!(
        "save-file",
        content::message::cli::SAVE_FILE_USAGE,
        command::save_file
    ),
    cli_command!(
        "delete-file",
        content::file_deletion::cli::DELETE_FILE_USAGE,
        command::delete_file
    ),
    cli_command!(
        "delete-message",
        content::message::cli::DELETE_MESSAGE_USAGE,
        command::delete_message
    ),
    cli_command!(
        "messages",
        content::message::cli::MESSAGES_USAGE,
        command::messages
    ),
    cli_command!("view", content::message::cli::VIEW_USAGE, command::view),
    cli_command!(
        "grant-admin",
        identity::admin::cli::GRANT_ADMIN_USAGE,
        command::grant_admin
    ),
    cli_command!(
        "generate",
        content::event::cli::GENERATE_USAGE,
        command::generate
    ),
    cli_command!(
        "generate-deps",
        sync::cascade_fact::cli::GENERATE_DEPS_USAGE,
        command::generate_deps
    ),
    cli_command!(
        "replay-deps-reverse",
        sync::cascade_fact::cli::REPLAY_DEPS_REVERSE_USAGE,
        command::replay_deps_reverse
    ),
    cli_command!(
        "sync-status",
        sync::shared_fact::cli::SYNC_STATUS_USAGE,
        command::sync_status
    ),
    cli_command!(
        "negentropy-drain",
        sync::shared_fact::cli::NEGENTROPY_DRAIN_USAGE,
        command::negentropy_drain
    ),
    cli_command!(
        "content-count",
        content::event::cli::CONTENT_COUNT_USAGE,
        command::content_count
    ),
    cli_command!("assert", assertions::ASSERT_USAGE, command::assert_cli),
    cli_command!("clock", crate::core::clock::CLOCK_USAGE, command::clock),
    cli_command!(
        "count",
        identity::workspace::cli::COUNT_USAGE,
        command::count
    ),
];

pub(crate) const COMMAND_EXCLUDED_HANDLER_ROUTES: &[&str] = &[
    "send_facts_on_connection",
    "send_network_frame",
    "receive_transit_frame",
];

pub const SCHEMAS: &[SchemaRegistration] = &[
    SchemaRegistration {
        name: "core",
        source: CORE_SCHEMA_SOURCE,
    },
    SchemaRegistration {
        name: "network",
        source: network::SCHEMA_SOURCE,
    },
    SchemaRegistration {
        name: "facts",
        source: FACTS_SCHEMA_SOURCE,
    },
    SchemaRegistration {
        name: "intents",
        source: INTENTS_SCHEMA_SOURCE,
    },
];

macro_rules! fact {
    ($module:literal, $name:literal, $tag:path, $projector:literal) => {
        FactRegistration {
            module: $module,
            name: $name,
            tag: $tag,
            projector: $projector,
        }
    };
}

pub const FACTS: &[FactRegistration] = &[
    fact!(
        "sync::cascade_fact",
        "cascade_fact",
        sync::cascade_fact::layout::TYPE_CASCADE_FACT,
        "CascadeFactProjector"
    ),
    fact!(
        "connection::ephemeral_secret",
        "ephemeral_secret",
        connection::ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET,
        "ConnectionEphemeralSecretProjector"
    ),
    fact!(
        "connection::request",
        "request",
        connection::request::layout::TYPE_CONNECTION_REQUEST,
        "ConnectionRequestProjector"
    ),
    fact!(
        "connection::response",
        "response",
        connection::response::layout::TYPE_CONNECTION_RESPONSE,
        "ConnectionResponseProjector"
    ),
    fact!(
        "content::event",
        "event",
        content::event::layout::TYPE_CONTENT_EVENT,
        "ContentEventProjector"
    ),
    fact!(
        "content::file",
        "file",
        content::file::layout::TYPE_CONTENT_FILE,
        "ContentFileProjector"
    ),
    fact!(
        "content::file_deletion",
        "file_deletion",
        content::file_deletion::layout::TYPE_CONTENT_FILE_DELETION,
        "ContentFileDeletionProjector"
    ),
    fact!(
        "content::file_slice",
        "file_slice",
        content::file_slice::layout::TYPE_CONTENT_FILE_SLICE,
        "ContentFileSliceProjector"
    ),
    fact!(
        "content::message",
        "message",
        content::message::layout::TYPE_CONTENT_MESSAGE,
        "ContentMessageProjector"
    ),
    fact!(
        "content::message_deletion",
        "message_deletion",
        content::message_deletion::layout::TYPE_CONTENT_MESSAGE_DELETION,
        "ContentMessageDeletionProjector"
    ),
    fact!(
        "content::reaction",
        "reaction",
        content::reaction::layout::TYPE_CONTENT_REACTION,
        "ContentReactionProjector"
    ),
    fact!(
        "encryption::disappearing_messages_setting",
        "disappearing_messages_setting",
        encryption::disappearing_messages_setting::layout::TYPE_DISAPPEARING_MESSAGES_SETTING,
        "DisappearingMessagesSettingProjector"
    ),
    fact!(
        "encryption",
        "recipient_key",
        encryption::layout::TYPE_RECIPIENT_KEY,
        "EncryptionProjector"
    ),
    fact!(
        "encryption",
        "removal_frontier",
        encryption::layout::TYPE_REMOVAL_FRONTIER,
        "EncryptionProjector"
    ),
    fact!(
        "encryption",
        "local_key_secret",
        encryption::layout::TYPE_LOCAL_KEY_SECRET,
        "EncryptionProjector"
    ),
    fact!(
        "encryption",
        "local_history_node_secret",
        encryption::layout::TYPE_LOCAL_HISTORY_NODE_SECRET,
        "EncryptionProjector"
    ),
    fact!(
        "encryption",
        "key_request",
        encryption::layout::TYPE_KEY_REQUEST,
        "EncryptionProjector"
    ),
    fact!(
        "encryption",
        "key_wrap",
        encryption::layout::TYPE_KEY_WRAP,
        "EncryptionProjector"
    ),
    fact!(
        "encryption",
        "local_recipient_key",
        encryption::layout::TYPE_LOCAL_RECIPIENT_KEY,
        "EncryptionProjector"
    ),
    fact!(
        "identity::admin",
        "admin",
        identity::admin::layout::TYPE_ADMIN,
        "AdminProjector"
    ),
    fact!(
        "identity::device_invite",
        "device_invite",
        identity::device_invite::layout::TYPE_DEVICE_INVITE,
        "DeviceInviteProjector"
    ),
    fact!(
        "identity::endpoint",
        "local_endpoint",
        identity::endpoint::layout::TYPE_LOCAL_ENDPOINT,
        "EndpointProjector"
    ),
    fact!(
        "identity::endpoint_shared",
        "endpoint_shared",
        identity::endpoint_shared::layout::TYPE_ENDPOINT_SHARED,
        "EndpointSharedProjector"
    ),
    fact!(
        "identity::invite",
        "invite_secret",
        identity::invite::layout::TYPE_INVITE_SECRET,
        "InviteSecretProjector"
    ),
    fact!(
        "identity::invite_accepted",
        "invite_accepted",
        identity::invite_accepted::layout::TYPE_INVITE_ACCEPTED,
        "InviteAcceptedProjector"
    ),
    fact!(
        "identity::invite_server",
        "invite_server",
        identity::invite_server::layout::TYPE_INVITE_SERVER,
        "InviteServerProjector"
    ),
    fact!(
        "identity::user",
        "user",
        identity::user::layout::TYPE_USER,
        "UserProjector"
    ),
    fact!(
        "identity::user_invite",
        "user_invite",
        identity::user_invite::layout::TYPE_USER_INVITE,
        "UserInviteProjector"
    ),
    fact!(
        "identity::workspace",
        "workspace",
        identity::workspace::layout::TYPE_WORKSPACE,
        "WorkspaceProjector"
    ),
    fact!(
        "encryption::local_history_node_secret",
        "local_history_node_secret",
        encryption::local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET,
        "LocalHistoryNodeSecretProjector"
    ),
    fact!(
        "encryption::removal_frontier",
        "removal_frontier",
        encryption::removal_frontier::layout::TYPE_REMOVAL_FRONTIER,
        "RemovalFrontierProjector"
    ),
    fact!(
        "identity::signed_fact",
        "signed_fact",
        identity::signed_fact::layout::TYPE_SIGNED_FACT,
        "SignedFactProjector"
    ),
    fact!(
        "identity::signed_fact",
        "local_signer_secret",
        identity::signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET,
        "SignedFactProjector"
    ),
    fact!(
        "sync::range_request",
        "range_request",
        sync::range_request::layout::TYPE_SYNC_RANGE_REQUEST,
        "SyncRangeRequestProjector"
    ),
    fact!(
        "sync::encrypted_root",
        "encrypted_root",
        sync::encrypted_root::layout::TYPE_ENCRYPTED_ROOT,
        "SyncEncryptedRootProjector"
    ),
    fact!(
        "sync::shared_fact",
        "shared_fact",
        sync::shared_fact::layout::TYPE_SHARED_FACT,
        "SyncSharedFactProjector"
    ),
    fact!(
        "sync::key_wrap_available",
        "key_wrap_available",
        sync::key_wrap_available::layout::TYPE_KEY_WRAP_AVAILABLE,
        "SyncKeyWrapAvailableProjector"
    ),
    fact!(
        "sync::compare",
        "compare",
        sync::compare::layout::TYPE_SYNC_COMPARE,
        "SyncCompareProjector"
    ),
    fact!(
        "sync::have_id",
        "have_id",
        sync::have_id::layout::TYPE_SYNC_HAVE_ID,
        "SyncHaveIdProjector"
    ),
    fact!(
        "sync::need_id",
        "need_id",
        sync::need_id::layout::TYPE_SYNC_NEED_ID,
        "SyncNeedIdProjector"
    ),
    fact!(
        "transport::transit_received",
        "transit_received",
        transport::transit_received::layout::TYPE_TRANSIT_RECEIVED,
        "TransitReceivedProjector"
    ),
];

pub const CONTEXT_MATCHERS: &[ContextRoleDeclaration] = &[
    ContextRoleDeclaration::exact(matchers::CONNECTION_EPHEMERAL_SECRET_ROLE),
    ContextRoleDeclaration::exact(matchers::CONNECTION_INVITE_SECRET_ROLE),
    ContextRoleDeclaration::exact(matchers::CONNECTION_REQUEST_ROLE),
    ContextRoleDeclaration::exact(matchers::CONTENT_FILE_ROLE),
    ContextRoleDeclaration::exact(matchers::CONTENT_MESSAGE_ROLE),
    ContextRoleDeclaration::exact(matchers::CONTENT_MESSAGE_META_ROLE),
    ContextRoleDeclaration::exact(matchers::CONTENT_DELETED_ROLE),
    ContextRoleDeclaration::exact(matchers::IDENTITY_ADMIN_ROLE),
    ContextRoleDeclaration::exact(matchers::IDENTITY_DEVICE_INVITE_ROLE),
    ContextRoleDeclaration::exact(matchers::IDENTITY_DEVICE_INVITE_KEY_ROLE),
    ContextRoleDeclaration::exact(matchers::IDENTITY_ENDPOINT_SHARED_ROLE),
    ContextRoleDeclaration::exact(matchers::IDENTITY_INVITE_SECRET_ROLE),
    ContextRoleDeclaration::exact(matchers::IDENTITY_INVITE_SERVER_ROLE),
    ContextRoleDeclaration::exact(matchers::IDENTITY_INVITE_SERVER_KEY_ROLE),
    ContextRoleDeclaration::exact(matchers::IDENTITY_USER_ROLE),
    ContextRoleDeclaration::exact(matchers::IDENTITY_USER_INVITE_ROLE),
    ContextRoleDeclaration::exact(matchers::IDENTITY_USER_INVITE_KEY_ROLE),
    ContextRoleDeclaration::exact(matchers::IDENTITY_WORKSPACE_ROLE),
    ContextRoleDeclaration::exact(matchers::LOCAL_RECIPIENT_KEY_ROLE),
    ContextRoleDeclaration::exact(matchers::LOCAL_SECRET_SOURCE_ROLE),
    ContextRoleDeclaration::exact(matchers::LOCAL_SIGNER_SECRET_ROLE),
    ContextRoleDeclaration::exact(matchers::RECIPIENT_KEY_ROLE),
    ContextRoleDeclaration::exact(matchers::RECIPIENT_SUPERSEDED_ROLE),
    ContextRoleDeclaration::exact(matchers::REMOVAL_FRONTIER_ROLE),
    matchers::SECRET_COVERAGE_CONTEXT_ROLE,
    ContextRoleDeclaration::exact(matchers::CONTENT_SIGNER_ROLE),
    ContextRoleDeclaration::exact(matchers::SYNC_EXACT_FACT_ROLE),
    ContextRoleDeclaration::exact(matchers::SYNC_KEY_WRAP_ROLE),
    matchers::RANGE_FACT_CONTEXT_ROLE,
    ContextRoleDeclaration::exact(matchers::TRANSIT_RECEIVED_ROLE),
    matchers::WRAP_SOURCE_CONTEXT_ROLE,
];

pub const INTENTS: &[IntentRegistration] = &[
    IntentRegistration {
        kind: connection_intents::send_bootstrap_request::SEND_BOOTSTRAP_CONNECTION_REQUEST,
        queue: IntentQueueKind::Local,
        declared_by: "intents::connection::send_bootstrap_request",
    },
    IntentRegistration {
        kind: connection_intents::create_response::CREATE_CONNECTION_RESPONSE,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::connection::create_response",
    },
    IntentRegistration {
        kind: encryption::intent::CREATE_KEY_WRAP,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::encryption::create_key_wrap",
    },
    IntentRegistration {
        kind: encryption::intent::PURGE_RETIRED_RECIPIENT_MATERIAL,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::encryption::purge_retired_recipient_material",
    },
    IntentRegistration {
        kind: encryption::intent::UNWRAP_KEY_WRAP,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::encryption::unwrap_key_wrap",
    },
    IntentRegistration {
        kind: sync_intents::send_compare_response::SEND_SYNC_COMPARE_RESPONSE,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::sync::send_compare_response",
    },
    IntentRegistration {
        kind: sync_intents::send_needed_fact_id::SEND_NEEDED_FACT_ID,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::sync::send_needed_fact_id",
    },
    IntentRegistration {
        kind: sync_intents::send_requested_fact::SEND_REQUESTED_FACT,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::sync::send_requested_fact",
    },
    IntentRegistration {
        kind: sync_intents::share_fact_with_workspace::SHARE_FACT_WITH_WORKSPACE,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::sync::share_fact_with_workspace",
    },
    IntentRegistration {
        kind: sync_intents::seed_connection::SEED_CONNECTION_SYNC,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::sync::seed_connection",
    },
    IntentRegistration {
        kind: transport_intents::send_facts_on_connection::SEND_FACTS_ON_CONNECTION,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::transport::send_facts_on_connection",
    },
    IntentRegistration {
        kind: transport_intents::send_network_frame::SEND_NETWORK_FRAME,
        queue: IntentQueueKind::Local,
        declared_by: "intents::transport::send_network_frame",
    },
    IntentRegistration {
        kind: transport_intents::receive_transit_frame::RECEIVE_TRANSIT_FRAME,
        queue: IntentQueueKind::Local,
        declared_by: "intents::transport::receive_transit_frame",
    },
    IntentRegistration {
        kind: content_intents::purge_deleted_message::PURGE_DELETED_MESSAGE,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::content::purge_deleted_message",
    },
    IntentRegistration {
        kind: content_intents::purge_message_child::PURGE_MESSAGE_CHILD,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::content::purge_message_child",
    },
    IntentRegistration {
        kind: content_intents::purge_expired_message::PURGE_EXPIRED_MESSAGE,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::content::purge_expired_message",
    },
    IntentRegistration {
        kind: content_intents::purge_below_retention_floor::PURGE_BELOW_RETENTION_FLOOR,
        queue: IntentQueueKind::Durable,
        declared_by: "intents::content::purge_below_retention_floor",
    },
];

macro_rules! handler_registration {
    ($module:literal, $handler:literal, $runtime_field:literal, [$($intent:path),+ $(,)?]) => {
        HandlerRegistration {
            module: $module,
            handler: $handler,
            runtime_field: $runtime_field,
            intents: &[$($intent),+],
        }
    };
}

pub const HANDLERS: &[HandlerRegistration] = &[
    handler_registration!(
        "connection::send_bootstrap_request",
        "SendBootstrapConnectionRequestHandler",
        "send_bootstrap_connection_request",
        [connection_intents::send_bootstrap_request::SEND_BOOTSTRAP_CONNECTION_REQUEST]
    ),
    handler_registration!(
        "connection::create_response",
        "CreateConnectionResponseHandler",
        "create_connection_response",
        [connection_intents::create_response::CREATE_CONNECTION_RESPONSE]
    ),
    handler_registration!(
        "sync::send_compare_response",
        "SendSyncCompareResponseHandler",
        "send_sync_compare_response",
        [sync_intents::send_compare_response::SEND_SYNC_COMPARE_RESPONSE]
    ),
    handler_registration!(
        "sync::send_needed_fact_id",
        "SendNeededFactIdHandler",
        "send_needed_fact_id",
        [sync_intents::send_needed_fact_id::SEND_NEEDED_FACT_ID]
    ),
    handler_registration!(
        "sync::send_requested_fact",
        "SendRequestedFactHandler",
        "send_requested_fact",
        [sync_intents::send_requested_fact::SEND_REQUESTED_FACT]
    ),
    handler_registration!(
        "sync::share_fact_with_workspace",
        "ShareFactWithWorkspaceHandler",
        "share_fact_with_workspace",
        [sync_intents::share_fact_with_workspace::SHARE_FACT_WITH_WORKSPACE]
    ),
    handler_registration!(
        "sync::seed_connection",
        "SeedConnectionSyncHandler",
        "seed_connection_sync",
        [sync_intents::seed_connection::SEED_CONNECTION_SYNC]
    ),
    handler_registration!(
        "encryption::create_key_wrap",
        "CreateKeyWrapHandler",
        "create_key_wrap",
        [encryption::intent::CREATE_KEY_WRAP]
    ),
    handler_registration!(
        "encryption::purge_retired_recipient_material",
        "PurgeRetiredRecipientMaterialHandler",
        "purge_retired_recipient_material",
        [encryption::intent::PURGE_RETIRED_RECIPIENT_MATERIAL]
    ),
    handler_registration!(
        "encryption::unwrap_key_wrap",
        "UnwrapKeyWrapHandler",
        "unwrap_key_wrap",
        [encryption::intent::UNWRAP_KEY_WRAP]
    ),
    handler_registration!(
        "content::purge_deleted_message",
        "PurgeDeletedMessageHandler",
        "purge_deleted_message",
        [content_intents::purge_deleted_message::PURGE_DELETED_MESSAGE]
    ),
    handler_registration!(
        "content::purge_message_child",
        "PurgeMessageChildHandler",
        "purge_message_child",
        [content_intents::purge_message_child::PURGE_MESSAGE_CHILD]
    ),
    handler_registration!(
        "content::purge_expired_message",
        "PurgeExpiredMessageHandler",
        "purge_expired_message",
        [content_intents::purge_expired_message::PURGE_EXPIRED_MESSAGE]
    ),
    handler_registration!(
        "content::purge_below_retention_floor",
        "PurgeBelowRetentionFloorHandler",
        "purge_below_retention_floor",
        [content_intents::purge_below_retention_floor::PURGE_BELOW_RETENTION_FLOOR]
    ),
    handler_registration!(
        "transport::send_facts_on_connection",
        "SendFactsOnConnectionHandler",
        "send_facts_on_connection",
        [transport_intents::send_facts_on_connection::SEND_FACTS_ON_CONNECTION]
    ),
    handler_registration!(
        "transport::send_network_frame",
        "SendNetworkFrameHandler",
        "send_network_frame",
        [transport_intents::send_network_frame::SEND_NETWORK_FRAME]
    ),
    handler_registration!(
        "transport::receive_transit_frame",
        "ReceiveTransitFrameHandler",
        "receive_transit_frame",
        [transport_intents::receive_transit_frame::RECEIVE_TRANSIT_FRAME]
    ),
];

pub(crate) const SCHEMA_SOURCES: &[&str] = &[
    network::SCHEMA_SOURCE,
    FACTS_SCHEMA_SOURCE,
    INTENTS_SCHEMA_SOURCE,
];

pub(crate) const ROW_MUTATION_TABLES: &[TableName] = &[
    sync::cascade_fact::rows::CASCADE_STAGED_FACT_ROWS,
    connection::ephemeral_secret::rows::CONNECTION_EPHEMERAL_SECRET_ROWS,
    connection::request::rows::CONNECTION_REQUEST_ROWS,
    connection::response::rows::CONNECTION_RESPONSE_ROWS,
    content::event::rows::CONTENT_EVENT_ROWS,
    content::file::rows::FILE_ROWS,
    content::file_deletion::rows::FILE_DELETION_ROWS,
    content::file_slice::rows::FILE_SLICE_ROWS,
    content::message::rows::CONTENT_MESSAGE_ROWS,
    content::message_deletion::rows::MESSAGE_DELETION_ROWS,
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
    content::message::rows::OPENED_MESSAGE_ROWS,
    content::message::rows::MESSAGE_TOMBSTONE_ROWS,
    sync::compare::rows::SYNC_COMPARE_ROWS,
    sync::have_id::rows::SYNC_HAVE_ID_ROWS,
    sync::need_id::rows::SYNC_NEED_ID_ROWS,
];

pub(crate) fn protocol_projector() -> Box<dyn Projector> {
    Box::new(ProtocolProjector)
}

pub(crate) fn protocol_context_matchers() -> Vec<Box<dyn ContextMatcher>> {
    ProtocolContextMatchers::new().into_matchers()
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProtocolProjector;

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

macro_rules! projector_routes {
    ($($name:ident => $tag:path, $projector:path;)+) => {
        $(projector_route!($name, $projector);)+

        const FACT_ROUTES: &[FactRoute] = &[
            $(FactRoute {
                tag: $tag,
                projector: $name,
            },)+
        ];
    };
}

projector_routes! {
    project_cascade_fact => sync::cascade_fact::layout::TYPE_CASCADE_FACT, sync::cascade_fact::project::CascadeFactProjector;
    project_connection_ephemeral_secret => connection::ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET, connection::ephemeral_secret::project::ConnectionEphemeralSecretProjector;
    project_connection_request => connection::request::layout::TYPE_CONNECTION_REQUEST, connection::request::project::ConnectionRequestProjector;
    project_connection_response => connection::response::layout::TYPE_CONNECTION_RESPONSE, connection::response::project::ConnectionResponseProjector;
    project_content_event => content::event::layout::TYPE_CONTENT_EVENT, content::event::project::ContentEventProjector;
    project_content_file => content::file::layout::TYPE_CONTENT_FILE, content::file::project::ContentFileProjector;
    project_content_file_deletion => content::file_deletion::layout::TYPE_CONTENT_FILE_DELETION, content::file_deletion::project::ContentFileDeletionProjector;
    project_content_file_slice => content::file_slice::layout::TYPE_CONTENT_FILE_SLICE, content::file_slice::project::ContentFileSliceProjector;
    project_content_message => content::message::layout::TYPE_CONTENT_MESSAGE, content::message::project::ContentMessageProjector;
    project_content_message_deletion => content::message_deletion::layout::TYPE_CONTENT_MESSAGE_DELETION, content::message_deletion::project::ContentMessageDeletionProjector;
    project_content_reaction => content::reaction::layout::TYPE_CONTENT_REACTION, content::reaction::project::ContentReactionProjector;
    project_encryption_recipient_key => encryption::layout::TYPE_RECIPIENT_KEY, encryption::project::EncryptionProjector;
    project_encryption_removal_frontier => encryption::layout::TYPE_REMOVAL_FRONTIER, encryption::project::EncryptionProjector;
    project_encryption_local_key_secret => encryption::layout::TYPE_LOCAL_KEY_SECRET, encryption::project::EncryptionProjector;
    project_encryption_local_history_node_secret => encryption::layout::TYPE_LOCAL_HISTORY_NODE_SECRET, encryption::project::EncryptionProjector;
    project_encryption_key_request => encryption::layout::TYPE_KEY_REQUEST, encryption::project::EncryptionProjector;
    project_encryption_key_wrap => encryption::layout::TYPE_KEY_WRAP, encryption::project::EncryptionProjector;
    project_encryption_local_recipient_key => encryption::layout::TYPE_LOCAL_RECIPIENT_KEY, encryption::project::EncryptionProjector;
    project_endpoint => identity::endpoint::layout::TYPE_LOCAL_ENDPOINT, identity::endpoint::project::EndpointProjector;
    project_invite => identity::invite::layout::TYPE_INVITE_SECRET, identity::invite::project::InviteSecretProjector;
    project_workspace => identity::workspace::layout::TYPE_WORKSPACE, identity::workspace::project::WorkspaceProjector;
    project_signed_fact => identity::signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET, identity::signed_fact::project::SignedFactProjector;
    project_device_invite => identity::device_invite::layout::TYPE_DEVICE_INVITE, identity::device_invite::project::DeviceInviteProjector;
    project_endpoint_shared => identity::endpoint_shared::layout::TYPE_ENDPOINT_SHARED, identity::endpoint_shared::project::EndpointSharedProjector;
    project_invite_server => identity::invite_server::layout::TYPE_INVITE_SERVER, identity::invite_server::project::InviteServerProjector;
    project_admin => identity::admin::layout::TYPE_ADMIN, identity::admin::project::AdminProjector;
    project_invite_accepted => identity::invite_accepted::layout::TYPE_INVITE_ACCEPTED, identity::invite_accepted::project::InviteAcceptedProjector;
    project_disappearing_messages_setting => encryption::disappearing_messages_setting::layout::TYPE_DISAPPEARING_MESSAGES_SETTING, encryption::disappearing_messages_setting::project::DisappearingMessagesSettingProjector;
    project_sync_range_request => sync::range_request::layout::TYPE_SYNC_RANGE_REQUEST, sync::range_request::project::SyncRangeRequestProjector;
    project_sync_encrypted_root => sync::encrypted_root::layout::TYPE_ENCRYPTED_ROOT, sync::encrypted_root::project::SyncEncryptedRootProjector;
    project_sync_shared_fact => sync::shared_fact::layout::TYPE_SHARED_FACT, sync::shared_fact::project::SyncSharedFactProjector;
    project_sync_key_wrap_available => sync::key_wrap_available::layout::TYPE_KEY_WRAP_AVAILABLE, sync::key_wrap_available::project::SyncKeyWrapAvailableProjector;
    project_sync_compare => sync::compare::layout::TYPE_SYNC_COMPARE, sync::compare::project::SyncCompareProjector;
    project_sync_have_id => sync::have_id::layout::TYPE_SYNC_HAVE_ID, sync::have_id::project::SyncHaveIdProjector;
    project_sync_need_id => sync::need_id::layout::TYPE_SYNC_NEED_ID, sync::need_id::project::SyncNeedIdProjector;
    project_transit_received => transport::transit_received::layout::TYPE_TRANSIT_RECEIVED, transport::transit_received::project::TransitReceivedProjector;
    project_user_invite => identity::user_invite::layout::TYPE_USER_INVITE, identity::user_invite::project::UserInviteProjector;
    project_user => identity::user::layout::TYPE_USER, identity::user::project::UserProjector;
    project_local_history_node_secret => encryption::local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET, encryption::local_history_node_secret::project::LocalHistoryNodeSecretProjector;
    project_removal_frontier => encryption::removal_frontier::layout::TYPE_REMOVAL_FRONTIER, encryption::removal_frontier::project::RemovalFrontierProjector;
}

fn signed_effective_tag(fact: &Fact) -> Result<u8, String> {
    Ok(identity::signed_fact::layout::decode_signed_fact(&fact.bytes)?.inner_type)
}

const ENVELOPE_ROUTES: &[EnvelopeRoute] = &[EnvelopeRoute {
    outer_tag: identity::signed_fact::layout::TYPE_SIGNED_FACT,
    effective_tag: signed_effective_tag,
}];

pub struct ProtocolContextMatchers {
    matchers: Vec<Box<dyn ContextMatcher>>,
}

impl ProtocolContextMatchers {
    fn new() -> Self {
        let mut exact_roles = BTreeSet::<Role>::new();
        let mut custom_roles = BTreeSet::<&'static str>::new();
        for declaration in CONTEXT_MATCHERS {
            match declaration.matcher {
                ContextMatcherDeclaration::ExactSelector => {
                    exact_roles.insert(
                        Role::new(declaration.role).expect("registered exact matcher role"),
                    );
                }
                ContextMatcherDeclaration::SelectOnlySql { .. } => {
                    custom_roles.insert(declaration.role);
                }
            }
        }

        let mut matchers: Vec<Box<dyn ContextMatcher>> =
            exact_roles.into_iter().map(exact_matcher).collect();
        for role in custom_roles {
            match role {
                matchers::SYNC_RANGE_FACT_ROLE => {
                    matchers.push(Box::new(matchers::RangeFactMatcher::new()));
                }
                matchers::SECRET_COVERAGE_ROLE => {
                    matchers.push(Box::new(matchers::SecretCoverageMatcher::new()));
                }
                matchers::WRAP_SOURCE_ROLE => {
                    matchers.push(Box::new(matchers::WrapSourceMatcher::new()));
                }
                other => panic!("unknown custom context matcher role {other}"),
            }
        }
        Self { matchers }
    }

    #[cfg(test)]
    fn matcher_refs(&self) -> Vec<&dyn ContextMatcher> {
        self.matchers
            .iter()
            .map(|matcher| matcher.as_ref() as &dyn ContextMatcher)
            .collect()
    }

    fn into_matchers(self) -> Vec<Box<dyn ContextMatcher>> {
        self.matchers
    }
}

fn exact_matcher(role: Role) -> Box<dyn ContextMatcher> {
    Box::new(ExactSelectorMatcher::new(role))
}

macro_rules! handler_route {
    ($name:literal, $intent_kind:path, $handler:path) => {
        HandlerRoute {
            name: $name,
            intent_kind: $intent_kind,
            factory: || Box::new(<$handler>::new()),
        }
    };
}

pub(crate) const HANDLER_ROUTES: &[HandlerRoute] = &[
    handler_route!(
        "send_bootstrap_connection_request",
        connection_intents::send_bootstrap_request::SEND_BOOTSTRAP_CONNECTION_REQUEST,
        connection_intents::send_bootstrap_request::SendBootstrapConnectionRequestHandler
    ),
    handler_route!(
        "create_connection_response",
        connection_intents::create_response::CREATE_CONNECTION_RESPONSE,
        connection_intents::create_response::CreateConnectionResponseHandler
    ),
    handler_route!(
        "send_sync_compare_response",
        sync_intents::send_compare_response::SEND_SYNC_COMPARE_RESPONSE,
        sync_intents::send_compare_response::SendSyncCompareResponseHandler
    ),
    handler_route!(
        "send_needed_fact_id",
        sync_intents::send_needed_fact_id::SEND_NEEDED_FACT_ID,
        sync_intents::send_needed_fact_id::SendNeededFactIdHandler
    ),
    handler_route!(
        "send_requested_fact",
        sync_intents::send_requested_fact::SEND_REQUESTED_FACT,
        sync_intents::send_requested_fact::SendRequestedFactHandler
    ),
    handler_route!(
        "share_fact_with_workspace",
        sync_intents::share_fact_with_workspace::SHARE_FACT_WITH_WORKSPACE,
        sync_intents::share_fact_with_workspace::ShareFactWithWorkspaceHandler
    ),
    handler_route!(
        "seed_connection_sync",
        sync_intents::seed_connection::SEED_CONNECTION_SYNC,
        sync_intents::seed_connection::SeedConnectionSyncHandler
    ),
    handler_route!(
        "create_key_wrap",
        encryption::intent::CREATE_KEY_WRAP,
        encryption_intents::create_key_wrap::CreateKeyWrapHandler
    ),
    handler_route!(
        "purge_retired_recipient_material",
        encryption::intent::PURGE_RETIRED_RECIPIENT_MATERIAL,
        encryption_intents::purge_retired_recipient_material::PurgeRetiredRecipientMaterialHandler
    ),
    handler_route!(
        "unwrap_key_wrap",
        encryption::intent::UNWRAP_KEY_WRAP,
        encryption_intents::unwrap_key_wrap::UnwrapKeyWrapHandler
    ),
    handler_route!(
        "purge_deleted_message",
        content_intents::purge_deleted_message::PURGE_DELETED_MESSAGE,
        content_intents::purge_deleted_message::PurgeDeletedMessageHandler
    ),
    handler_route!(
        "purge_message_child",
        content_intents::purge_message_child::PURGE_MESSAGE_CHILD,
        content_intents::purge_message_child::PurgeMessageChildHandler
    ),
    handler_route!(
        "purge_expired_message",
        content_intents::purge_expired_message::PURGE_EXPIRED_MESSAGE,
        content_intents::purge_expired_message::PurgeExpiredMessageHandler
    ),
    handler_route!(
        "purge_below_retention_floor",
        content_intents::purge_below_retention_floor::PURGE_BELOW_RETENTION_FLOOR,
        content_intents::purge_below_retention_floor::PurgeBelowRetentionFloorHandler
    ),
    handler_route!(
        "send_facts_on_connection",
        transport_intents::send_facts_on_connection::SEND_FACTS_ON_CONNECTION,
        transport_intents::send_facts_on_connection::SendFactsOnConnectionHandler
    ),
    handler_route!(
        "send_network_frame",
        transport_intents::send_network_frame::SEND_NETWORK_FRAME,
        transport_intents::send_network_frame::SendNetworkFrameHandler
    ),
    handler_route!(
        "receive_transit_frame",
        transport_intents::receive_transit_frame::RECEIVE_TRANSIT_FRAME,
        transport_intents::receive_transit_frame::ReceiveTransitFrameHandler
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_runtime_matchers_follow_registry_exact_roles() {
        let runtime_matchers = ProtocolContextMatchers::new();
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
            .filter(|declaration| {
                matches!(
                    declaration.matcher,
                    ContextMatcherDeclaration::ExactSelector
                )
            })
            .map(|declaration| declaration.role.to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(runtime_roles, registry_roles);
    }
}
