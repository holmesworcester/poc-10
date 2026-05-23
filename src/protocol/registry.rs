//! Declarative registry for the target protocol.
//!
//! This is the protocol's integration boundary. Core can run any protocol that
//! supplies schema sources, projector routes, handler routes, row mutation
//! tables, and user-facing commands. This file assembles those
//! declarations for the poc-10 protocol and hands them to `protocol::app` and
//! the generic runtime.
//!
//! The registry should read like a table of contents, not like an
//! implementation file. Fact modules own layouts, projectors, rows, queries,
//! and commands. Intent modules own payloads, idempotence keys, and handlers.
//! Context helper modules own relationship semantics. The registry names those
//! pieces once so core can route facts by tag, route intents by kind, apply
//! schemas, and validate row mutation targets.
//!
//! Add a new fact family here after its module has supplied a layout tag,
//! projector, schema rows, and any context roles it needs. Add a new intent
//! here after its module has supplied the payload layout and handler. If this
//! file starts needing protocol policy branches, move that logic back to the
//! module that owns the policy and keep this file declarative.

use crate::core::cli::CliCommand;
use crate::core::facts::Fact;
use crate::core::intents::TypedTableSchema;
use crate::core::network;
use crate::core::projectors::{
    EnvelopeRoute, FactRoute, ProjectionContext, ProjectionOutput, Projector, RouterProjector,
};
use crate::core::runtime::HandlerRoute;
use crate::core::store::{SchemaSource, TableName};
use crate::protocol::cli as command;
use crate::protocol::{connection, content, encryption, identity, sync};

pub use crate::protocol::cli::MatchCliContext;

pub(crate) mod read_models {
    use super::{TableName, TypedTableSchema};

    macro_rules! typed_table {
        (
            $schema:ident,
            $table_const:ident,
            $table_name:literal,
            columns [$($column:literal),+ $(,)?],
            key [$($key_column:literal),+ $(,)?]
        ) => {
            pub const $schema: TypedTableSchema = TypedTableSchema {
                table: TableName::new($table_name),
                columns: &[$($column),+],
                key_columns: &[$($key_column),+],
            };

            pub const $table_const: TableName = $schema.table;
        };
    }

    typed_table!(
        OPENED_MESSAGES,
        OPENED_MESSAGE_ROWS,
        "opened_message_rows",
        columns [
            "workspace_id",
            "message_id",
            "created_at_ms",
            "author_user_id",
            "signer_id",
            "text",
        ],
        key ["workspace_id", "message_id"]
    );

    typed_table!(
        MESSAGE_TOMBSTONES,
        MESSAGE_TOMBSTONE_ROWS,
        "message_tombstone_rows",
        columns [
            "workspace_id",
            "message_id",
            "author_user_id",
            "authored_minute",
        ],
        key ["workspace_id", "message_id"]
    );

    typed_table!(
        FILE_SLICES,
        FILE_SLICE_ROWS,
        "file_slice_rows",
        columns [
            "workspace_id",
            "file_id",
            "slice_index",
            "slice_fact_id",
            "created_at_ms",
            "ciphertext",
        ],
        key ["workspace_id", "file_id", "slice_index"]
    );

    typed_table!(
        CONTENT_EVENTS,
        CONTENT_EVENT_ROWS,
        "content_event_rows",
        columns ["workspace_id", "fact_id", "timestamp", "payload_bytes"],
        key ["workspace_id", "fact_id"]
    );

    typed_table!(
        CONTENT_MESSAGES,
        CONTENT_MESSAGE_ROWS,
        "content_messages",
        columns [
            "workspace_id",
            "message_id",
            "author_user_id",
            "created_at_ms",
            "signer_id",
            "frontier_id",
            "minute",
            "leaf_id",
            "deleted",
        ],
        key ["workspace_id", "message_id"]
    );

    typed_table!(
        CONTENT_REACTIONS,
        REACTION_ROWS,
        "content_reactions",
        columns [
            "workspace_id",
            "reaction_id",
            "message_id",
            "author_user_id",
            "created_at_ms",
            "nonce",
            "ciphertext",
            "deleted",
        ],
        key ["workspace_id", "reaction_id"]
    );

    typed_table!(
        CONTENT_FILES,
        FILE_ROWS,
        "content_files",
        columns [
            "workspace_id",
            "file_fact_id",
            "message_id",
            "file_id",
            "author_user_id",
            "created_at_ms",
            "root_hash",
            "byte_len",
            "total_slices",
            "slice_bytes",
            "sealed_metadata",
            "deleted",
        ],
        key ["workspace_id", "file_fact_id"]
    );

    typed_table!(
        MESSAGE_DELETIONS,
        MESSAGE_DELETION_ROWS,
        "message_deletion_rows",
        columns [
            "workspace_id",
            "target_message_id",
            "deletion_id",
            "created_at_ms",
            "author_user_id",
        ],
        key ["workspace_id", "target_message_id"]
    );

    typed_table!(
        FILE_DELETIONS,
        FILE_DELETION_ROWS,
        "file_deletion_rows",
        columns [
            "workspace_id",
            "target_file_id",
            "deletion_id",
            "created_at_ms",
            "author_user_id",
        ],
        key ["workspace_id", "target_file_id"]
    );
}

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

CREATE TABLE IF NOT EXISTS disappearing_messages_setting_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
"#,
    row_tables: &[
        identity::workspace::rows::WORKSPACE_ROWS,
        encryption::key_wrap::rows::KEY_WRAP_ROWS,
        identity::user::rows::USER_ROWS,
        identity::endpoint::rows::LOCAL_ENDPOINT_ROWS,
        identity::endpoint::rows::LOCAL_ENDPOINT_SECRET_ROWS,
        identity::endpoint::rows::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
        identity::endpoint::rows::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS,
        identity::endpoint_shared::rows::ENDPOINT_SHARED_ROWS,
        sync::cascade_test_fact::rows::CASCADE_STAGED_FACT_ROWS,
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
        encryption::disappearing_messages_setting::rows::DISAPPEARING_MESSAGES_SETTING_ROWS,
    ],
};

// Every CLI command's host function must live in `protocol::cli`. This macro
// takes the run function as a bare identifier and resolves it against the
// `command` (`protocol::cli`) module, so registering a command whose handler
// lives anywhere else simply does not compile.
macro_rules! cli_command {
    ($name:literal, $usage:path, $run:ident) => {
        CliCommand {
            name: $name,
            usage: $usage,
            help: "",
            run: command::$run,
        }
    };
}

pub const MATCH_COMMANDS: &[CliCommand<MatchCliContext>] = &[
    cli_command!(
        "create-workspace",
        identity::workspace::cli::CREATE_WORKSPACE_USAGE,
        create_workspace
    ),
    cli_command!("invite", identity::invite::cli::INVITE_USAGE, invite),
    cli_command!(
        "invite-server",
        identity::invite::cli::INVITE_SERVER_USAGE,
        invite_server
    ),
    cli_command!("accept", identity::invite::cli::ACCEPT_USAGE, accept),
    cli_command!(
        "accept-invite-server",
        identity::invite::cli::ACCEPT_INVITE_SERVER_USAGE,
        accept_invite_server
    ),
    cli_command!("link", identity::invite::cli::LINK_USAGE, link),
    cli_command!(
        "accept-link",
        identity::invite::cli::ACCEPT_LINK_USAGE,
        accept_link
    ),
    cli_command!(
        "identity",
        identity::endpoint_shared::cli::IDENTITY_USAGE,
        identity
    ),
    cli_command!("peers", identity::endpoint_shared::cli::PEERS_USAGE, peers),
    cli_command!(
        "workspaces",
        identity::workspace::cli::WORKSPACES_USAGE,
        workspaces
    ),
    cli_command!("users", identity::user::cli::USERS_USAGE, users),
    cli_command!(
        "key-recipient",
        encryption::key_wrap::cli::KEY_RECIPIENT_USAGE,
        key_recipient
    ),
    cli_command!(
        "key-rotate-recipient",
        encryption::key_wrap::cli::KEY_ROTATE_RECIPIENT_USAGE,
        key_recipient_rotation
    ),
    cli_command!(
        "key-frontier",
        encryption::key_wrap::cli::KEY_FRONTIER_USAGE,
        key_frontier
    ),
    cli_command!(
        "key-wrap",
        encryption::key_wrap::cli::KEY_WRAP_USAGE,
        key_wrap
    ),
    cli_command!(
        "key-access",
        encryption::key_wrap::cli::KEY_ACCESS_USAGE,
        key_access
    ),
    cli_command!(
        "key-derive",
        encryption::key_wrap::cli::KEY_DERIVE_USAGE,
        key_derive
    ),
    cli_command!(
        "key-node",
        encryption::key_wrap::cli::KEY_NODE_USAGE,
        key_node
    ),
    cli_command!("keys", encryption::key_wrap::cli::KEYS_USAGE, keys),
    cli_command!(
        "chop-now",
        encryption::key_wrap::cli::CHOP_NOW_USAGE,
        chop_now
    ),
    cli_command!(
        "disappearing-set",
        encryption::disappearing_messages_setting::cli::DISAPPEARING_SET_USAGE,
        disappearing_set
    ),
    cli_command!(
        "disappearing-status",
        encryption::disappearing_messages_setting::cli::DISAPPEARING_STATUS_USAGE,
        disappearing_status
    ),
    cli_command!(
        "disappearing-tighten",
        encryption::disappearing_messages_setting::cli::DISAPPEARING_TIGHTEN_USAGE,
        disappearing_tighten
    ),
    cli_command!(
        "disappearing-compact",
        encryption::disappearing_messages_setting::cli::DISAPPEARING_COMPACT_USAGE,
        disappearing_compact
    ),
    cli_command!("send", content::message::cli::SEND_USAGE, send),
    cli_command!("react", content::message::cli::REACT_USAGE, react),
    cli_command!(
        "send-file",
        content::message::cli::SEND_FILE_USAGE,
        send_file
    ),
    cli_command!("files", content::message::cli::FILES_USAGE, files),
    cli_command!(
        "save-file",
        content::message::cli::SAVE_FILE_USAGE,
        save_file
    ),
    cli_command!(
        "delete-file",
        content::file_deletion::cli::DELETE_FILE_USAGE,
        delete_file
    ),
    cli_command!(
        "delete-message",
        content::message::cli::DELETE_MESSAGE_USAGE,
        delete_message
    ),
    cli_command!("messages", content::message::cli::MESSAGES_USAGE, messages),
    cli_command!("view", content::message::cli::VIEW_USAGE, view),
    cli_command!(
        "grant-admin",
        identity::admin::cli::GRANT_ADMIN_USAGE,
        grant_admin
    ),
    cli_command!("generate", content::message::cli::GENERATE_USAGE, generate),
    cli_command!(
        "generate-deps",
        sync::cascade_test_fact::cli::GENERATE_DEPS_USAGE,
        generate_deps
    ),
    cli_command!(
        "replay-deps-reverse",
        sync::cascade_test_fact::cli::REPLAY_DEPS_REVERSE_USAGE,
        replay_deps_reverse
    ),
    cli_command!(
        "sync-status",
        sync::shared_fact::cli::SYNC_STATUS_USAGE,
        sync_status
    ),
    cli_command!(
        "negentropy-drain",
        sync::shared_fact::cli::NEGENTROPY_DRAIN_USAGE,
        negentropy_drain
    ),
    cli_command!(
        "content-count",
        content::message::cli::CONTENT_COUNT_USAGE,
        content_count
    ),
    cli_command!("clock", crate::core::clock::CLOCK_USAGE, clock),
    cli_command!("count", identity::workspace::cli::COUNT_USAGE, count),
];

pub(crate) const COMMAND_EXCLUDED_HANDLER_ROUTES: &[&str] = &[
    "send_facts_on_connection",
    "send_network_frame",
    "receive_network_frame",
];

pub(crate) const SCHEMA_SOURCES: &[SchemaSource] = &[network::SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE];

pub(crate) const ROW_MUTATION_TABLES: &[TableName] = &[
    sync::cascade_test_fact::rows::CASCADE_STAGED_FACT_ROWS,
    connection::ephemeral_secret::rows::CONNECTION_EPHEMERAL_SECRET_ROWS,
    connection::request::rows::CONNECTION_REQUEST_ROWS,
    connection::response::rows::CONNECTION_RESPONSE_ROWS,
    read_models::CONTENT_EVENT_ROWS,
    read_models::FILE_ROWS,
    read_models::FILE_DELETION_ROWS,
    read_models::FILE_SLICE_ROWS,
    read_models::CONTENT_MESSAGE_ROWS,
    read_models::MESSAGE_DELETION_ROWS,
    read_models::REACTION_ROWS,
    encryption::disappearing_messages_setting::rows::DISAPPEARING_MESSAGES_SETTING_ROWS,
    encryption::key_wrap::rows::KEY_WRAP_ROWS,
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
    read_models::OPENED_MESSAGE_ROWS,
    read_models::MESSAGE_TOMBSTONE_ROWS,
    sync::compare::rows::SYNC_COMPARE_ROWS,
    sync::have_id::rows::SYNC_HAVE_ID_ROWS,
    sync::need_id::rows::SYNC_NEED_ID_ROWS,
];

pub(crate) fn protocol_projector() -> Box<dyn Projector> {
    Box::new(ProtocolProjector)
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
    project_cascade_test_fact => sync::cascade_test_fact::layout::TYPE_CASCADE_TEST_FACT, sync::cascade_test_fact::project::CascadeTestFactProjector;
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
    project_encryption_recipient_key => encryption::recipient_key::layout::TYPE_RECIPIENT_KEY, encryption::recipient_key::project::RecipientKeyProjector;
    project_encryption_removal_frontier => encryption::removal_frontier::layout::TYPE_REMOVAL_FRONTIER, encryption::removal_frontier::project::RemovalFrontierProjector;
    project_encryption_local_key_secret => encryption::local_key_secret::layout::TYPE_LOCAL_KEY_SECRET, encryption::local_key_secret::project::LocalKeySecretProjector;
    project_encryption_local_history_node_secret => encryption::local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET, encryption::local_history_node_secret::project::LocalHistoryNodeSecretProjector;
    project_encryption_key_request => encryption::key_request::layout::TYPE_KEY_REQUEST, encryption::key_request::project::KeyRequestProjector;
    project_encryption_key_wrap => encryption::key_wrap::layout::TYPE_KEY_WRAP, encryption::key_wrap::project::KeyWrapProjector;
    project_encryption_local_recipient_key => encryption::local_recipient_key::layout::TYPE_LOCAL_RECIPIENT_KEY, encryption::local_recipient_key::project::LocalRecipientKeyProjector;
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
    project_connection_frame_small => connection::frame::layout::TYPE_CONNECTION_FRAME_SMALL, connection::frame::project::ConnectionFrameProjector;
    project_connection_frame_large => connection::frame::layout::TYPE_CONNECTION_FRAME_LARGE, connection::frame::project::ConnectionFrameProjector;
    project_connection_fact_receipt => connection::fact_receipt::layout::TYPE_CONNECTION_FACT_RECEIPT, connection::fact_receipt::project::ConnectionFactReceiptProjector;
    project_user_invite => identity::user_invite::layout::TYPE_USER_INVITE, identity::user_invite::project::UserInviteProjector;
    project_user => identity::user::layout::TYPE_USER, identity::user::project::UserProjector;
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
        connection::send_bootstrap_request::SEND_BOOTSTRAP_CONNECTION_REQUEST,
        connection::send_bootstrap_request::SendBootstrapConnectionRequestHandler
    ),
    handler_route!(
        "create_connection_response",
        connection::create_response::CREATE_CONNECTION_RESPONSE,
        connection::create_response::CreateConnectionResponseHandler
    ),
    handler_route!(
        "send_sync_compare_response",
        sync::send_compare_response::SEND_SYNC_COMPARE_RESPONSE,
        sync::send_compare_response::SendSyncCompareResponseHandler
    ),
    handler_route!(
        "send_needed_fact_id",
        sync::send_needed_fact_id::SEND_NEEDED_FACT_ID,
        sync::send_needed_fact_id::SendNeededFactIdHandler
    ),
    handler_route!(
        "send_requested_fact",
        sync::send_requested_fact::SEND_REQUESTED_FACT,
        sync::send_requested_fact::SendRequestedFactHandler
    ),
    handler_route!(
        "share_fact_with_workspace",
        sync::share_fact_with_workspace::SHARE_FACT_WITH_WORKSPACE,
        sync::share_fact_with_workspace::ShareFactWithWorkspaceHandler
    ),
    handler_route!(
        "seed_connection_sync",
        sync::seed_connection::SEED_CONNECTION_SYNC,
        sync::seed_connection::SeedConnectionSyncHandler
    ),
    handler_route!(
        "create_key_wrap",
        encryption::create_key_wrap::CREATE_KEY_WRAP,
        encryption::create_key_wrap::CreateKeyWrapHandler
    ),
    handler_route!(
        "purge_retired_recipient_material",
        encryption::purge_retired_recipient_material::PURGE_RETIRED_RECIPIENT_MATERIAL,
        encryption::purge_retired_recipient_material::PurgeRetiredRecipientMaterialHandler
    ),
    handler_route!(
        "unwrap_key_wrap",
        encryption::unwrap_key_wrap::UNWRAP_KEY_WRAP,
        encryption::unwrap_key_wrap::UnwrapKeyWrapHandler
    ),
    handler_route!(
        "purge_deleted_message",
        content::purge_deleted_message::PURGE_DELETED_MESSAGE,
        content::purge_deleted_message::PurgeDeletedMessageHandler
    ),
    handler_route!(
        "purge_message_child",
        content::purge_message_child::PURGE_MESSAGE_CHILD,
        content::purge_message_child::PurgeMessageChildHandler
    ),
    handler_route!(
        "purge_expired_message",
        content::purge_expired_message::PURGE_EXPIRED_MESSAGE,
        content::purge_expired_message::PurgeExpiredMessageHandler
    ),
    handler_route!(
        "purge_below_retention_floor",
        content::purge_below_retention_floor::PURGE_BELOW_RETENTION_FLOOR,
        content::purge_below_retention_floor::PurgeBelowRetentionFloorHandler
    ),
    handler_route!(
        "send_facts_on_connection",
        connection::send_facts_on_connection::SEND_FACTS_ON_CONNECTION,
        connection::send_facts_on_connection::SendFactsOnConnectionHandler
    ),
    handler_route!(
        "send_network_frame",
        connection::send_network_frame::SEND_NETWORK_FRAME,
        connection::send_network_frame::SendNetworkFrameHandler
    ),
    handler_route!(
        "receive_network_frame",
        connection::receive_network_frame::RECEIVE_NETWORK_FRAME,
        connection::receive_network_frame::ReceiveNetworkFrameHandler
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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
