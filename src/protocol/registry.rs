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
use crate::core::projectors::{
    EnvelopeRoute, FactRoute, ProjectionContext, ProjectionOutput, Projector, RouterProjector,
};
use crate::core::runtime::HandlerRoute;
use crate::core::schema::CORE_SCHEMA_SOURCE;
use crate::core::store::TableName;
use crate::protocol::cli as command;
use crate::protocol::facts::{connection, content, encryption, identity, sync, transport};
use crate::protocol::intents::{
    connection as connection_intents, content as content_intents, encryption as encryption_intents,
    sync as sync_intents, transport as transport_intents,
};
use crate::protocol::matchers;
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

pub const MATCH_COMMANDS: &[CliCommand<MatchCliContext>] = &[
    CliCommand {
        name: "create-workspace",
        usage: identity::workspace::cli::CREATE_WORKSPACE_USAGE,
        help: "",
        run: command::create_workspace,
    },
    CliCommand {
        name: "invite",
        usage: identity::invite::cli::INVITE_USAGE,
        help: "",
        run: command::invite,
    },
    CliCommand {
        name: "invite-server",
        usage: identity::invite::cli::INVITE_SERVER_USAGE,
        help: "",
        run: command::invite_server,
    },
    CliCommand {
        name: "accept",
        usage: identity::invite::cli::ACCEPT_USAGE,
        help: "",
        run: command::accept,
    },
    CliCommand {
        name: "accept-invite-server",
        usage: identity::invite::cli::ACCEPT_INVITE_SERVER_USAGE,
        help: "",
        run: command::accept_invite_server,
    },
    CliCommand {
        name: "link",
        usage: identity::invite::cli::LINK_USAGE,
        help: "",
        run: command::link,
    },
    CliCommand {
        name: "accept-link",
        usage: identity::invite::cli::ACCEPT_LINK_USAGE,
        help: "",
        run: command::accept_link,
    },
    CliCommand {
        name: "identity",
        usage: identity::endpoint_shared::cli::IDENTITY_USAGE,
        help: "",
        run: command::identity,
    },
    CliCommand {
        name: "peers",
        usage: identity::endpoint_shared::cli::PEERS_USAGE,
        help: "",
        run: command::peers,
    },
    CliCommand {
        name: "workspaces",
        usage: identity::workspace::cli::WORKSPACES_USAGE,
        help: "",
        run: command::workspaces,
    },
    CliCommand {
        name: "users",
        usage: identity::user::cli::USERS_USAGE,
        help: "",
        run: command::users,
    },
    CliCommand {
        name: "key-recipient",
        usage: encryption::cli::KEY_RECIPIENT_USAGE,
        help: "",
        run: command::key_recipient,
    },
    CliCommand {
        name: "key-rotate-recipient",
        usage: encryption::cli::KEY_ROTATE_RECIPIENT_USAGE,
        help: "",
        run: command::key_recipient_rotation,
    },
    CliCommand {
        name: "key-frontier",
        usage: encryption::cli::KEY_FRONTIER_USAGE,
        help: "",
        run: command::key_frontier,
    },
    CliCommand {
        name: "key-wrap",
        usage: encryption::cli::KEY_WRAP_USAGE,
        help: "",
        run: command::key_wrap,
    },
    CliCommand {
        name: "key-access",
        usage: encryption::cli::KEY_ACCESS_USAGE,
        help: "",
        run: command::key_access,
    },
    CliCommand {
        name: "key-derive",
        usage: encryption::cli::KEY_DERIVE_USAGE,
        help: "",
        run: command::key_derive,
    },
    CliCommand {
        name: "key-node",
        usage: encryption::cli::KEY_NODE_USAGE,
        help: "",
        run: command::key_node,
    },
    CliCommand {
        name: "keys",
        usage: encryption::cli::KEYS_USAGE,
        help: "",
        run: command::keys,
    },
    CliCommand {
        name: "chop-now",
        usage: encryption::cli::CHOP_NOW_USAGE,
        help: "",
        run: command::chop_now,
    },
    CliCommand {
        name: "disappearing-set",
        usage: encryption::disappearing_messages_setting::cli::DISAPPEARING_SET_USAGE,
        help: "",
        run: command::disappearing_set,
    },
    CliCommand {
        name: "disappearing-status",
        usage: encryption::disappearing_messages_setting::cli::DISAPPEARING_STATUS_USAGE,
        help: "",
        run: command::disappearing_status,
    },
    CliCommand {
        name: "disappearing-tighten",
        usage: encryption::disappearing_messages_setting::cli::DISAPPEARING_TIGHTEN_USAGE,
        help: "",
        run: command::disappearing_tighten,
    },
    CliCommand {
        name: "disappearing-compact",
        usage: encryption::disappearing_messages_setting::cli::DISAPPEARING_COMPACT_USAGE,
        help: "",
        run: command::disappearing_compact,
    },
    CliCommand {
        name: "send",
        usage: content::message::cli::SEND_USAGE,
        help: "",
        run: command::send,
    },
    CliCommand {
        name: "react",
        usage: content::message::cli::REACT_USAGE,
        help: "",
        run: command::react,
    },
    CliCommand {
        name: "send-file",
        usage: content::message::cli::SEND_FILE_USAGE,
        help: "",
        run: command::send_file,
    },
    CliCommand {
        name: "files",
        usage: content::message::cli::FILES_USAGE,
        help: "",
        run: command::files,
    },
    CliCommand {
        name: "save-file",
        usage: content::message::cli::SAVE_FILE_USAGE,
        help: "",
        run: command::save_file,
    },
    CliCommand {
        name: "delete-file",
        usage: content::file_deletion::cli::DELETE_FILE_USAGE,
        help: "",
        run: command::delete_file,
    },
    CliCommand {
        name: "delete-message",
        usage: content::message::cli::DELETE_MESSAGE_USAGE,
        help: "",
        run: command::delete_message,
    },
    CliCommand {
        name: "messages",
        usage: content::message::cli::MESSAGES_USAGE,
        help: "",
        run: command::messages,
    },
    CliCommand {
        name: "view",
        usage: content::message::cli::VIEW_USAGE,
        help: "",
        run: command::view,
    },
    CliCommand {
        name: "grant-admin",
        usage: identity::admin::cli::GRANT_ADMIN_USAGE,
        help: "",
        run: command::grant_admin,
    },
    CliCommand {
        name: "generate",
        usage: content::event::cli::GENERATE_USAGE,
        help: "",
        run: command::generate,
    },
    CliCommand {
        name: "generate-deps",
        usage: sync::cascade_fact::cli::GENERATE_DEPS_USAGE,
        help: "",
        run: command::generate_deps,
    },
    CliCommand {
        name: "replay-deps-reverse",
        usage: sync::cascade_fact::cli::REPLAY_DEPS_REVERSE_USAGE,
        help: "",
        run: command::replay_deps_reverse,
    },
    CliCommand {
        name: "sync-status",
        usage: sync::shared_fact::cli::SYNC_STATUS_USAGE,
        help: "",
        run: command::sync_status,
    },
    CliCommand {
        name: "negentropy-drain",
        usage: sync::shared_fact::cli::NEGENTROPY_DRAIN_USAGE,
        help: "",
        run: command::negentropy_drain,
    },
    CliCommand {
        name: "content-count",
        usage: content::event::cli::CONTENT_COUNT_USAGE,
        help: "",
        run: command::content_count,
    },
    CliCommand {
        name: "clock",
        usage: crate::core::clock::CLOCK_USAGE,
        help: "",
        run: command::clock,
    },
    CliCommand {
        name: "count",
        usage: identity::workspace::cli::COUNT_USAGE,
        help: "",
        run: command::count,
    },
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
        name: "facts",
        source: FACTS_SCHEMA_SOURCE,
    },
    SchemaRegistration {
        name: "intents",
        source: INTENTS_SCHEMA_SOURCE,
    },
];

pub const FACTS: &[FactRegistration] = &[
    FactRegistration {
        module: "sync::cascade_fact",
        name: "cascade_fact",
        tag: sync::cascade_fact::layout::TYPE_CASCADE_FACT,
        projector: "CascadeFactProjector",
    },
    FactRegistration {
        module: "connection::ephemeral_secret",
        name: "ephemeral_secret",
        tag: connection::ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET,
        projector: "ConnectionEphemeralSecretProjector",
    },
    FactRegistration {
        module: "connection::request",
        name: "request",
        tag: connection::request::layout::TYPE_CONNECTION_REQUEST,
        projector: "ConnectionRequestProjector",
    },
    FactRegistration {
        module: "connection::response",
        name: "response",
        tag: connection::response::layout::TYPE_CONNECTION_RESPONSE,
        projector: "ConnectionResponseProjector",
    },
    FactRegistration {
        module: "content::event",
        name: "event",
        tag: content::event::layout::TYPE_CONTENT_EVENT,
        projector: "ContentEventProjector",
    },
    FactRegistration {
        module: "content::file",
        name: "file",
        tag: content::file::layout::TYPE_CONTENT_FILE,
        projector: "ContentFileProjector",
    },
    FactRegistration {
        module: "content::file_deletion",
        name: "file_deletion",
        tag: content::file_deletion::layout::TYPE_CONTENT_FILE_DELETION,
        projector: "ContentFileDeletionProjector",
    },
    FactRegistration {
        module: "content::file_slice",
        name: "file_slice",
        tag: content::file_slice::layout::TYPE_CONTENT_FILE_SLICE,
        projector: "ContentFileSliceProjector",
    },
    FactRegistration {
        module: "content::message",
        name: "message",
        tag: content::message::layout::TYPE_CONTENT_MESSAGE,
        projector: "ContentMessageProjector",
    },
    FactRegistration {
        module: "content::message_deletion",
        name: "message_deletion",
        tag: content::message_deletion::layout::TYPE_CONTENT_MESSAGE_DELETION,
        projector: "ContentMessageDeletionProjector",
    },
    FactRegistration {
        module: "content::reaction",
        name: "reaction",
        tag: content::reaction::layout::TYPE_CONTENT_REACTION,
        projector: "ContentReactionProjector",
    },
    FactRegistration {
        module: "encryption::disappearing_messages_setting",
        name: "disappearing_messages_setting",
        tag: encryption::disappearing_messages_setting::layout::TYPE_DISAPPEARING_MESSAGES_SETTING,
        projector: "DisappearingMessagesSettingProjector",
    },
    FactRegistration {
        module: "encryption",
        name: "recipient_key",
        tag: encryption::layout::TYPE_RECIPIENT_KEY,
        projector: "EncryptionProjector",
    },
    FactRegistration {
        module: "encryption",
        name: "removal_frontier",
        tag: encryption::layout::TYPE_REMOVAL_FRONTIER,
        projector: "EncryptionProjector",
    },
    FactRegistration {
        module: "encryption",
        name: "local_key_secret",
        tag: encryption::layout::TYPE_LOCAL_KEY_SECRET,
        projector: "EncryptionProjector",
    },
    FactRegistration {
        module: "encryption",
        name: "local_history_node_secret",
        tag: encryption::layout::TYPE_LOCAL_HISTORY_NODE_SECRET,
        projector: "EncryptionProjector",
    },
    FactRegistration {
        module: "encryption",
        name: "key_request",
        tag: encryption::layout::TYPE_KEY_REQUEST,
        projector: "EncryptionProjector",
    },
    FactRegistration {
        module: "encryption",
        name: "key_wrap",
        tag: encryption::layout::TYPE_KEY_WRAP,
        projector: "EncryptionProjector",
    },
    FactRegistration {
        module: "encryption",
        name: "local_recipient_key",
        tag: encryption::layout::TYPE_LOCAL_RECIPIENT_KEY,
        projector: "EncryptionProjector",
    },
    FactRegistration {
        module: "identity::admin",
        name: "admin",
        tag: identity::admin::layout::TYPE_ADMIN,
        projector: "AdminProjector",
    },
    FactRegistration {
        module: "identity::device_invite",
        name: "device_invite",
        tag: identity::device_invite::layout::TYPE_DEVICE_INVITE,
        projector: "DeviceInviteProjector",
    },
    FactRegistration {
        module: "identity::endpoint",
        name: "local_endpoint",
        tag: identity::endpoint::layout::TYPE_LOCAL_ENDPOINT,
        projector: "EndpointProjector",
    },
    FactRegistration {
        module: "identity::endpoint_shared",
        name: "endpoint_shared",
        tag: identity::endpoint_shared::layout::TYPE_ENDPOINT_SHARED,
        projector: "EndpointSharedProjector",
    },
    FactRegistration {
        module: "identity::invite",
        name: "invite_secret",
        tag: identity::invite::layout::TYPE_INVITE_SECRET,
        projector: "InviteSecretProjector",
    },
    FactRegistration {
        module: "identity::invite_accepted",
        name: "invite_accepted",
        tag: identity::invite_accepted::layout::TYPE_INVITE_ACCEPTED,
        projector: "InviteAcceptedProjector",
    },
    FactRegistration {
        module: "identity::invite_server",
        name: "invite_server",
        tag: identity::invite_server::layout::TYPE_INVITE_SERVER,
        projector: "InviteServerProjector",
    },
    FactRegistration {
        module: "identity::user",
        name: "user",
        tag: identity::user::layout::TYPE_USER,
        projector: "UserProjector",
    },
    FactRegistration {
        module: "identity::user_invite",
        name: "user_invite",
        tag: identity::user_invite::layout::TYPE_USER_INVITE,
        projector: "UserInviteProjector",
    },
    FactRegistration {
        module: "identity::workspace",
        name: "workspace",
        tag: identity::workspace::layout::TYPE_WORKSPACE,
        projector: "WorkspaceProjector",
    },
    FactRegistration {
        module: "encryption::local_history_node_secret",
        name: "local_history_node_secret",
        tag: encryption::local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET,
        projector: "LocalHistoryNodeSecretProjector",
    },
    FactRegistration {
        module: "encryption::removal_frontier",
        name: "removal_frontier",
        tag: encryption::removal_frontier::layout::TYPE_REMOVAL_FRONTIER,
        projector: "RemovalFrontierProjector",
    },
    FactRegistration {
        module: "identity::signed_fact",
        name: "signed_fact",
        tag: identity::signed_fact::layout::TYPE_SIGNED_FACT,
        projector: "SignedFactProjector",
    },
    FactRegistration {
        module: "identity::signed_fact",
        name: "local_signer_secret",
        tag: identity::signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET,
        projector: "SignedFactProjector",
    },
    FactRegistration {
        module: "sync::range_request",
        name: "range_request",
        tag: sync::range_request::layout::TYPE_SYNC_RANGE_REQUEST,
        projector: "SyncRangeRequestProjector",
    },
    FactRegistration {
        module: "sync::encrypted_root",
        name: "encrypted_root",
        tag: sync::encrypted_root::layout::TYPE_ENCRYPTED_ROOT,
        projector: "SyncEncryptedRootProjector",
    },
    FactRegistration {
        module: "sync::shared_fact",
        name: "shared_fact",
        tag: sync::shared_fact::layout::TYPE_SHARED_FACT,
        projector: "SyncSharedFactProjector",
    },
    FactRegistration {
        module: "sync::key_wrap_available",
        name: "key_wrap_available",
        tag: sync::key_wrap_available::layout::TYPE_KEY_WRAP_AVAILABLE,
        projector: "SyncKeyWrapAvailableProjector",
    },
    FactRegistration {
        module: "sync::compare",
        name: "compare",
        tag: sync::compare::layout::TYPE_SYNC_COMPARE,
        projector: "SyncCompareProjector",
    },
    FactRegistration {
        module: "sync::have_id",
        name: "have_id",
        tag: sync::have_id::layout::TYPE_SYNC_HAVE_ID,
        projector: "SyncHaveIdProjector",
    },
    FactRegistration {
        module: "sync::need_id",
        name: "need_id",
        tag: sync::need_id::layout::TYPE_SYNC_NEED_ID,
        projector: "SyncNeedIdProjector",
    },
    FactRegistration {
        module: "transport::transit_received",
        name: "transit_received",
        tag: transport::transit_received::layout::TYPE_TRANSIT_RECEIVED,
        projector: "TransitReceivedProjector",
    },
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

pub const HANDLERS: &[HandlerRegistration] = &[
    HandlerRegistration {
        module: "connection::send_bootstrap_request",
        handler: "SendBootstrapConnectionRequestHandler",
        runtime_field: "send_bootstrap_connection_request",
        intents: &[connection_intents::send_bootstrap_request::SEND_BOOTSTRAP_CONNECTION_REQUEST],
    },
    HandlerRegistration {
        module: "connection::create_response",
        handler: "CreateConnectionResponseHandler",
        runtime_field: "create_connection_response",
        intents: &[connection_intents::create_response::CREATE_CONNECTION_RESPONSE],
    },
    HandlerRegistration {
        module: "sync::send_compare_response",
        handler: "SendSyncCompareResponseHandler",
        runtime_field: "send_sync_compare_response",
        intents: &[sync_intents::send_compare_response::SEND_SYNC_COMPARE_RESPONSE],
    },
    HandlerRegistration {
        module: "sync::send_needed_fact_id",
        handler: "SendNeededFactIdHandler",
        runtime_field: "send_needed_fact_id",
        intents: &[sync_intents::send_needed_fact_id::SEND_NEEDED_FACT_ID],
    },
    HandlerRegistration {
        module: "sync::send_requested_fact",
        handler: "SendRequestedFactHandler",
        runtime_field: "send_requested_fact",
        intents: &[sync_intents::send_requested_fact::SEND_REQUESTED_FACT],
    },
    HandlerRegistration {
        module: "sync::share_fact_with_workspace",
        handler: "ShareFactWithWorkspaceHandler",
        runtime_field: "share_fact_with_workspace",
        intents: &[sync_intents::share_fact_with_workspace::SHARE_FACT_WITH_WORKSPACE],
    },
    HandlerRegistration {
        module: "sync::seed_connection",
        handler: "SeedConnectionSyncHandler",
        runtime_field: "seed_connection_sync",
        intents: &[sync_intents::seed_connection::SEED_CONNECTION_SYNC],
    },
    HandlerRegistration {
        module: "encryption::create_key_wrap",
        handler: "CreateKeyWrapHandler",
        runtime_field: "create_key_wrap",
        intents: &[encryption::intent::CREATE_KEY_WRAP],
    },
    HandlerRegistration {
        module: "encryption::purge_retired_recipient_material",
        handler: "PurgeRetiredRecipientMaterialHandler",
        runtime_field: "purge_retired_recipient_material",
        intents: &[encryption::intent::PURGE_RETIRED_RECIPIENT_MATERIAL],
    },
    HandlerRegistration {
        module: "encryption::unwrap_key_wrap",
        handler: "UnwrapKeyWrapHandler",
        runtime_field: "unwrap_key_wrap",
        intents: &[encryption::intent::UNWRAP_KEY_WRAP],
    },
    HandlerRegistration {
        module: "content::purge_deleted_message",
        handler: "PurgeDeletedMessageHandler",
        runtime_field: "purge_deleted_message",
        intents: &[content_intents::purge_deleted_message::PURGE_DELETED_MESSAGE],
    },
    HandlerRegistration {
        module: "content::purge_message_child",
        handler: "PurgeMessageChildHandler",
        runtime_field: "purge_message_child",
        intents: &[content_intents::purge_message_child::PURGE_MESSAGE_CHILD],
    },
    HandlerRegistration {
        module: "content::purge_expired_message",
        handler: "PurgeExpiredMessageHandler",
        runtime_field: "purge_expired_message",
        intents: &[content_intents::purge_expired_message::PURGE_EXPIRED_MESSAGE],
    },
    HandlerRegistration {
        module: "content::purge_below_retention_floor",
        handler: "PurgeBelowRetentionFloorHandler",
        runtime_field: "purge_below_retention_floor",
        intents: &[content_intents::purge_below_retention_floor::PURGE_BELOW_RETENTION_FLOOR],
    },
    HandlerRegistration {
        module: "transport::send_facts_on_connection",
        handler: "SendFactsOnConnectionHandler",
        runtime_field: "send_facts_on_connection",
        intents: &[transport_intents::send_facts_on_connection::SEND_FACTS_ON_CONNECTION],
    },
    HandlerRegistration {
        module: "transport::send_network_frame",
        handler: "SendNetworkFrameHandler",
        runtime_field: "send_network_frame",
        intents: &[transport_intents::send_network_frame::SEND_NETWORK_FRAME],
    },
    HandlerRegistration {
        module: "transport::receive_transit_frame",
        handler: "ReceiveTransitFrameHandler",
        runtime_field: "receive_transit_frame",
        intents: &[transport_intents::receive_transit_frame::RECEIVE_TRANSIT_FRAME],
    },
];

pub(crate) const SCHEMA_SOURCES: &[&str] = &[FACTS_SCHEMA_SOURCE, INTENTS_SCHEMA_SOURCE];

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
    project_content_message,
    content::message::project::ContentMessageProjector
);
projector_route!(
    project_content_message_deletion,
    content::message_deletion::project::ContentMessageDeletionProjector
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
        tag: content::message::layout::TYPE_CONTENT_MESSAGE,
        projector: project_content_message,
    },
    FactRoute {
        tag: content::message_deletion::layout::TYPE_CONTENT_MESSAGE_DELETION,
        projector: project_content_message_deletion,
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

pub(crate) const HANDLER_ROUTES: &[HandlerRoute] = &[
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
