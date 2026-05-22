//! Declarative registry for the target protocol.
//!
//! This is the protocol's integration boundary. Core can run any protocol that
//! supplies schema sources, projector routes, context matchers, handler routes,
//! row mutation tables, and user-facing commands. This file assembles those
//! declarations for the poc-10 protocol and hands them to `protocol::app` and
//! the generic runtime.
//!
//! The registry should read like a table of contents, not like an
//! implementation file. Fact modules own layouts, projectors, rows, queries,
//! and commands. Intent modules own payloads, idempotence keys, and handlers.
//! Matcher modules own relationship semantics. The registry names those pieces
//! once so core can route facts by tag, route intents by kind, apply schemas,
//! and validate row mutation targets.
//!
//! Add a new fact family here after its module has supplied a layout tag,
//! projector, schema rows, and any context roles it needs. Add a new intent
//! here after its module has supplied the payload layout and handler. If this
//! file starts needing protocol policy branches, move that logic back to the
//! module that owns the policy and keep this file declarative.

use crate::core::cli::CliCommand;
use crate::core::facts::Fact;
use crate::core::matchers::{ContextMatcher, ContextMatchers};
use crate::core::network;
use crate::core::projectors::{
    EnvelopeRoute, FactRoute, ProjectionContext, ProjectionOutput, Projector, RouterProjector,
};
use crate::core::runtime::HandlerRoute;
use crate::core::store::{SchemaSource, TableName};
use crate::protocol::facts::{connection, content, encryption, identity, sync, transport};
use crate::protocol::intents::{
    connection as connection_intents, content as content_intents, encryption as encryption_intents,
    sync as sync_intents, transport as transport_intents,
};
use crate::protocol::matchers;
use crate::protocol::{assertions, cli as command};

pub use crate::protocol::cli::MatchCliContext;

pub const FACTS_SCHEMA_SOURCE: SchemaSource = SchemaSource {
    ddl: r#"
CREATE TABLE IF NOT EXISTS opened_message_rows (
    workspace_id BLOB NOT NULL,
    message_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    author_user_id BLOB NOT NULL,
    signer_id BLOB NOT NULL,
    text BLOB NOT NULL,
    PRIMARY KEY (workspace_id, message_id)
);
CREATE INDEX IF NOT EXISTS opened_message_rows_by_workspace_created
    ON opened_message_rows (workspace_id, created_at_ms);

CREATE TABLE IF NOT EXISTS message_tombstone_rows (
    workspace_id BLOB NOT NULL,
    message_id BLOB NOT NULL,
    author_user_id BLOB NOT NULL,
    authored_minute INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, message_id)
);
CREATE INDEX IF NOT EXISTS message_tombstone_rows_by_workspace_minute
    ON message_tombstone_rows (workspace_id, authored_minute);

CREATE TABLE IF NOT EXISTS file_slice_rows (
    workspace_id BLOB NOT NULL,
    file_id BLOB NOT NULL,
    slice_index INTEGER NOT NULL,
    slice_fact_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    PRIMARY KEY (workspace_id, file_id, slice_index)
);
CREATE INDEX IF NOT EXISTS file_slice_rows_by_fact
    ON file_slice_rows (slice_fact_id);

CREATE TABLE IF NOT EXISTS workspace_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS key_wrap_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS user_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS local_endpoint_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS local_endpoint_secret_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS local_endpoint_signing_public_key_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS local_endpoint_signing_secret_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS identity_endpoint_shared_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);

CREATE TABLE IF NOT EXISTS content_event_rows (
    workspace_id BLOB NOT NULL,
    fact_id BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    payload_bytes INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, fact_id)
);
CREATE INDEX IF NOT EXISTS content_event_rows_by_workspace_time
    ON content_event_rows (workspace_id, timestamp);

CREATE TABLE IF NOT EXISTS cascade_staged_fact_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS admin_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);

CREATE TABLE IF NOT EXISTS content_messages (
    workspace_id BLOB NOT NULL,
    message_id BLOB NOT NULL,
    author_user_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    signer_id BLOB NOT NULL,
    frontier_id BLOB NOT NULL,
    minute INTEGER NOT NULL,
    leaf_id BLOB NOT NULL,
    deleted INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, message_id)
);
CREATE INDEX IF NOT EXISTS content_messages_by_workspace_created
    ON content_messages (workspace_id, created_at_ms);

CREATE TABLE IF NOT EXISTS content_reactions (
    workspace_id BLOB NOT NULL,
    reaction_id BLOB NOT NULL,
    message_id BLOB NOT NULL,
    author_user_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    deleted INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, reaction_id)
);
CREATE INDEX IF NOT EXISTS content_reactions_by_message
    ON content_reactions (workspace_id, message_id, created_at_ms);

CREATE TABLE IF NOT EXISTS content_files (
    workspace_id BLOB NOT NULL,
    file_fact_id BLOB NOT NULL,
    message_id BLOB NOT NULL,
    file_id BLOB NOT NULL,
    author_user_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    root_hash BLOB NOT NULL,
    byte_len INTEGER NOT NULL,
    total_slices INTEGER NOT NULL,
    slice_bytes INTEGER NOT NULL,
    sealed_metadata BLOB NOT NULL,
    deleted INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, file_fact_id)
);
CREATE INDEX IF NOT EXISTS content_files_by_message
    ON content_files (workspace_id, message_id, created_at_ms);
CREATE INDEX IF NOT EXISTS content_files_by_file_id
    ON content_files (workspace_id, file_id);

CREATE TABLE IF NOT EXISTS connection_ephemeral_secret_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS connection_request_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS connection_response_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS invite_accepted_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS invite_server_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS user_invite_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS device_invite_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS invite_secret_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sync_compare_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sync_have_id_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sync_need_id_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sync_shareable_fact_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);

CREATE TABLE IF NOT EXISTS message_deletion_rows (
    workspace_id BLOB NOT NULL,
    target_message_id BLOB NOT NULL,
    deletion_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    author_user_id BLOB NOT NULL,
    PRIMARY KEY (workspace_id, target_message_id)
);
CREATE INDEX IF NOT EXISTS message_deletion_rows_by_deletion
    ON message_deletion_rows (deletion_id);

CREATE TABLE IF NOT EXISTS file_deletion_rows (
    workspace_id BLOB NOT NULL,
    target_file_id BLOB NOT NULL,
    deletion_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    author_user_id BLOB NOT NULL,
    PRIMARY KEY (workspace_id, target_file_id)
);
CREATE INDEX IF NOT EXISTS file_deletion_rows_by_deletion
    ON file_deletion_rows (deletion_id);

CREATE TABLE IF NOT EXISTS removal_frontier_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS local_history_node_secret_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS disappearing_messages_setting_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
"#,
    row_tables: &[
        identity::workspace::rows::WORKSPACE_ROWS,
        encryption::rows::KEY_WRAP_ROWS,
        identity::user::rows::USER_ROWS,
        identity::endpoint::rows::LOCAL_ENDPOINT_ROWS,
        identity::endpoint::rows::LOCAL_ENDPOINT_SECRET_ROWS,
        identity::endpoint::rows::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
        identity::endpoint::rows::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS,
        identity::endpoint_shared::rows::ENDPOINT_SHARED_ROWS,
        sync::cascade_fact::rows::CASCADE_STAGED_FACT_ROWS,
        identity::admin::rows::ADMIN_ROWS,
        connection::ephemeral_secret::rows::CONNECTION_EPHEMERAL_SECRET_ROWS,
        connection::request::rows::CONNECTION_REQUEST_ROWS,
        connection::response::rows::CONNECTION_RESPONSE_ROWS,
        identity::invite_accepted::rows::INVITE_ACCEPTED_ROWS,
        identity::invite_server::rows::INVITE_SERVER_ROWS,
        identity::user_invite::rows::USER_INVITE_ROWS,
        identity::device_invite::rows::DEVICE_INVITE_ROWS,
        identity::invite::rows::INVITE_SECRET_ROWS,
        sync::compare::rows::SYNC_COMPARE_ROWS,
        sync::have_id::rows::SYNC_HAVE_ID_ROWS,
        sync::need_id::rows::SYNC_NEED_ID_ROWS,
        sync::shared_fact::rows::SHAREABLE_FACT_ROWS,
        encryption::removal_frontier::rows::REMOVAL_FRONTIER_ROWS,
        encryption::local_history_node_secret::rows::LOCAL_HISTORY_NODE_SECRET_ROWS,
        encryption::disappearing_messages_setting::rows::DISAPPEARING_MESSAGES_SETTING_ROWS,
    ],
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

pub const EXACT_CONTEXT_ROLES: &[&str] = &[
    matchers::CONNECTION_EPHEMERAL_SECRET_ROLE,
    matchers::CONNECTION_INVITE_SECRET_ROLE,
    matchers::CONNECTION_REQUEST_ROLE,
    matchers::CONTENT_FILE_ROLE,
    matchers::CONTENT_MESSAGE_ROLE,
    matchers::CONTENT_MESSAGE_META_ROLE,
    matchers::CONTENT_DELETED_ROLE,
    matchers::IDENTITY_ADMIN_ROLE,
    matchers::IDENTITY_DEVICE_INVITE_ROLE,
    matchers::IDENTITY_DEVICE_INVITE_KEY_ROLE,
    matchers::IDENTITY_ENDPOINT_SHARED_ROLE,
    matchers::IDENTITY_INVITE_SECRET_ROLE,
    matchers::IDENTITY_INVITE_SERVER_ROLE,
    matchers::IDENTITY_INVITE_SERVER_KEY_ROLE,
    matchers::IDENTITY_USER_ROLE,
    matchers::IDENTITY_USER_INVITE_ROLE,
    matchers::IDENTITY_USER_INVITE_KEY_ROLE,
    matchers::IDENTITY_WORKSPACE_ROLE,
    matchers::LOCAL_RECIPIENT_KEY_ROLE,
    matchers::LOCAL_SECRET_SOURCE_ROLE,
    matchers::LOCAL_SIGNER_SECRET_ROLE,
    matchers::RECIPIENT_KEY_ROLE,
    matchers::RECIPIENT_SUPERSEDED_ROLE,
    matchers::REMOVAL_FRONTIER_ROLE,
    matchers::CONTENT_SIGNER_ROLE,
    matchers::SYNC_EXACT_FACT_ROLE,
    matchers::SYNC_KEY_WRAP_ROLE,
    matchers::TRANSIT_RECEIVED_ROLE,
];

pub const SQL_CONTEXT_ROLES: &[&str] = &[
    matchers::SECRET_COVERAGE_ROLE,
    matchers::SYNC_RANGE_FACT_ROLE,
    matchers::WRAP_SOURCE_ROLE,
];

pub(crate) const SCHEMA_SOURCES: &[SchemaSource] = &[network::SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE];

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

pub(crate) fn protocol_context_matchers() -> ContextMatchers {
    ContextMatchers::new(
        EXACT_CONTEXT_ROLES
            .iter()
            .copied()
            .map(matchers::protocol_role),
        vec![
            Box::new(matchers::SecretCoverageMatcher::new()) as Box<dyn ContextMatcher>,
            Box::new(matchers::RangeFactMatcher::new()),
            Box::new(matchers::WrapSourceMatcher::new()),
        ],
    )
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
    use std::collections::BTreeSet;

    #[test]
    fn protocol_runtime_matchers_follow_registry_exact_roles() {
        let runtime_matchers = protocol_context_matchers();
        let runtime_roles = runtime_matchers
            .exact_roles()
            .iter()
            .map(|role| role.as_str().to_string())
            .collect::<BTreeSet<_>>();
        let registry_roles = EXACT_CONTEXT_ROLES
            .iter()
            .map(|role| role.to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(runtime_roles, registry_roles);

        let custom_roles = runtime_matchers
            .custom()
            .map(|matcher| matcher.role().as_str().to_string())
            .collect::<BTreeSet<_>>();
        let sql_roles = SQL_CONTEXT_ROLES
            .iter()
            .map(|role| role.to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(custom_roles, sql_roles);
    }

    #[test]
    fn fact_route_tags_are_globally_unique() {
        let mut tags = BTreeSet::new();
        let duplicates = FACT_ROUTES
            .iter()
            .filter_map(|route| (!tags.insert(route.tag)).then_some(route.tag))
            .collect::<Vec<_>>();

        assert!(
            duplicates.is_empty(),
            "fact tags must be globally unique so runtime dispatch never guesses between fact types: {duplicates:?}"
        );
    }
}
