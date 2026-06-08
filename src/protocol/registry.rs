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
use crate::core::pipeline::{
    authenticate_authored, FactRoute, HandlerRoute, ProjectionContext, ProjectionOutput, Projector,
    RecurringIntentSpec, RouterProjector,
};
use crate::core::store::{ReplayTables, SchemaSource, TableName};
use crate::protocol::cli as command;
use crate::protocol::{auth, connection, content, sync};

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

macro_rules! authenticate_admission_arm {
    ($fact:expr, $codec:path, $authenticator:path) => {
        authenticate_authored::<$codec, $authenticator>($fact)
    };
}

/// Protocol-owned write admission gate for facts core is about to store.
///
/// Core calls this optionally from the runtime commit boundary. The registry
/// keeps the tag-to-family map here, but each family still owns the concrete
/// decode and authenticate implementation.
pub(crate) fn authenticate_fact_for_admission(fact: &Fact) -> Result<(), String> {
    let tag = fact
        .bytes
        .first()
        .copied()
        .ok_or_else(|| "cannot admit empty fact bytes".to_string())?;
    match tag {
        connection::close::encode::TYPE_CONNECTION_CLOSE => authenticate_admission_arm!(
            fact,
            connection::close::Codec,
            connection::close::authenticate::ConnectionCloseAuthenticator
        ),
        connection::ephemeral_secret::encode::TYPE_CONNECTION_EPHEMERAL_SECRET => {
            authenticate_admission_arm!(
                fact,
                connection::ephemeral_secret::Codec,
                connection::ephemeral_secret::authenticate::ConnectionEphemeralSecretAuthenticator
            )
        }
        connection::request::encode::TYPE_CONNECTION_REQUEST => authenticate_admission_arm!(
            fact,
            connection::request::Codec,
            connection::request::authenticate::ConnectionRequestAuthenticator
        ),
        connection::connection::encode::TYPE_CONNECTION => authenticate_admission_arm!(
            fact,
            connection::connection::Codec,
            connection::connection::authenticate::ConnectionAuthenticator
        ),
        content::file::encode::TYPE_CONTENT_FILE => authenticate_admission_arm!(
            fact,
            content::file::Codec,
            content::file::authenticate::ContentFileAuthenticator
        ),
        content::file_deletion::encode::TYPE_CONTENT_FILE_DELETION => authenticate_admission_arm!(
            fact,
            content::file_deletion::Codec,
            content::file_deletion::authenticate::ContentFileDeletionAuthenticator
        ),
        content::file_slice::encode::TYPE_CONTENT_FILE_SLICE => authenticate_admission_arm!(
            fact,
            content::file_slice::Codec,
            content::file_slice::authenticate::ContentFileSliceAuthenticator
        ),
        content::message::encode::TYPE_CONTENT_MESSAGE => authenticate_admission_arm!(
            fact,
            content::message::Codec,
            content::message::authenticate::ContentMessageAuthenticator
        ),
        content::message_deletion::encode::TYPE_CONTENT_MESSAGE_DELETION => {
            authenticate_admission_arm!(
                fact,
                content::message_deletion::Codec,
                content::message_deletion::authenticate::ContentMessageDeletionAuthenticator
            )
        }
        content::reaction::encode::TYPE_CONTENT_REACTION => authenticate_admission_arm!(
            fact,
            content::reaction::Codec,
            content::reaction::authenticate::ContentReactionAuthenticator
        ),
        auth::signature::encode::TYPE_SIGNATURE => authenticate_admission_arm!(
            fact,
            auth::signature::Codec,
            auth::signature::authenticate::SignatureAuthenticator
        ),
        auth::recipient_key::encode::TYPE_RECIPIENT_KEY => authenticate_admission_arm!(
            fact,
            auth::recipient_key::Codec,
            auth::recipient_key::authenticate::RecipientKeyAuthenticator
        ),
        auth::removal_frontier::encode::TYPE_REMOVAL_FRONTIER => authenticate_admission_arm!(
            fact,
            auth::removal_frontier::Codec,
            auth::removal_frontier::authenticate::RemovalFrontierAuthenticator
        ),
        auth::local_key_secret::encode::TYPE_LOCAL_KEY_SECRET => authenticate_admission_arm!(
            fact,
            auth::local_key_secret::Codec,
            auth::local_key_secret::authenticate::LocalKeySecretAuthenticator
        ),
        auth::local_history_node_secret::encode::TYPE_LOCAL_HISTORY_NODE_SECRET => {
            authenticate_admission_arm!(
                fact,
                auth::local_history_node_secret::Codec,
                auth::local_history_node_secret::authenticate::LocalHistoryNodeSecretAuthenticator
            )
        }
        auth::local_secret_retirement::encode::TYPE_LOCAL_SECRET_RETIREMENT => {
            authenticate_admission_arm!(
                fact,
                auth::local_secret_retirement::Codec,
                auth::local_secret_retirement::authenticate::LocalSecretRetirementAuthenticator
            )
        }
        auth::key_request::encode::TYPE_KEY_REQUEST => authenticate_admission_arm!(
            fact,
            auth::key_request::Codec,
            auth::key_request::authenticate::KeyRequestAuthenticator
        ),
        auth::key_wrap::encode::TYPE_KEY_WRAP => authenticate_admission_arm!(
            fact,
            auth::key_wrap::Codec,
            auth::key_wrap::authenticate::KeyWrapAuthenticator
        ),
        auth::local_recipient_key::encode::TYPE_LOCAL_RECIPIENT_KEY => {
            authenticate_admission_arm!(
                fact,
                auth::local_recipient_key::Codec,
                auth::local_recipient_key::authenticate::LocalRecipientKeyAuthenticator
            )
        }
        auth::endpoint::encode::TYPE_LOCAL_ENDPOINT => authenticate_admission_arm!(
            fact,
            auth::endpoint::Codec,
            auth::endpoint::authenticate::EndpointAuthenticator
        ),
        auth::invite::encode::TYPE_INVITE_SECRET => authenticate_admission_arm!(
            fact,
            auth::invite::Codec,
            auth::invite::authenticate::InviteSecretAuthenticator
        ),
        auth::workspace::encode::TYPE_WORKSPACE => authenticate_admission_arm!(
            fact,
            auth::workspace::Codec,
            auth::workspace::authenticate::WorkspaceAuthenticator
        ),
        auth::local_signer_secret::encode::TYPE_LOCAL_SIGNER_SECRET => authenticate_admission_arm!(
            fact,
            auth::local_signer_secret::Codec,
            auth::local_signer_secret::authenticate::LocalSignerSecretAuthenticator
        ),
        auth::device_invite::encode::TYPE_DEVICE_INVITE => authenticate_admission_arm!(
            fact,
            auth::device_invite::Codec,
            auth::device_invite::authenticate::DeviceInviteAuthenticator
        ),
        auth::endpoint_shared::encode::TYPE_ENDPOINT_SHARED => authenticate_admission_arm!(
            fact,
            auth::endpoint_shared::Codec,
            auth::endpoint_shared::authenticate::EndpointSharedAuthenticator
        ),
        auth::invite_server::encode::TYPE_INVITE_SERVER => authenticate_admission_arm!(
            fact,
            auth::invite_server::Codec,
            auth::invite_server::authenticate::InviteServerAuthenticator
        ),
        auth::admin::encode::TYPE_ADMIN => authenticate_admission_arm!(
            fact,
            auth::admin::Codec,
            auth::admin::authenticate::AdminAuthenticator
        ),
        auth::invite_accepted::encode::TYPE_INVITE_ACCEPTED => authenticate_admission_arm!(
            fact,
            auth::invite_accepted::Codec,
            auth::invite_accepted::authenticate::InviteAcceptedAuthenticator
        ),
        content::retention_policy::encode::TYPE_RETENTION_POLICY => authenticate_admission_arm!(
            fact,
            content::retention_policy::Codec,
            content::retention_policy::authenticate::RetentionPolicyAuthenticator
        ),
        sync::range_request::encode::TYPE_SYNC_RANGE_REQUEST => authenticate_admission_arm!(
            fact,
            sync::range_request::Codec,
            sync::range_request::authenticate::SyncRangeRequestAuthenticator
        ),
        sync::shared_fact::encode::TYPE_SHARED_FACT => authenticate_admission_arm!(
            fact,
            sync::shared_fact::Codec,
            sync::shared_fact::authenticate::SyncSharedFactAuthenticator
        ),
        sync::compare::encode::TYPE_SYNC_COMPARE => authenticate_admission_arm!(
            fact,
            sync::compare::Codec,
            sync::compare::authenticate::SyncCompareAuthenticator
        ),
        sync::have_id::encode::TYPE_SYNC_HAVE_ID => authenticate_admission_arm!(
            fact,
            sync::have_id::Codec,
            sync::have_id::authenticate::SyncHaveIdAuthenticator
        ),
        sync::need_id::encode::TYPE_SYNC_NEED_ID => authenticate_admission_arm!(
            fact,
            sync::need_id::Codec,
            sync::need_id::authenticate::SyncNeedIdAuthenticator
        ),
        connection::frame_small::encode::TYPE_CONNECTION_FRAME_SMALL => {
            authenticate_admission_arm!(
                fact,
                connection::frame_small::Codec,
                connection::frame_small::authenticate::ConnectionFrameSmallAuthenticator
            )
        }
        connection::frame_file_slice::encode::TYPE_CONNECTION_FRAME_FILE_SLICE => {
            authenticate_admission_arm!(
                fact,
                connection::frame_file_slice::Codec,
                connection::frame_file_slice::authenticate::ConnectionFrameFileSliceAuthenticator
            )
        }
        connection::frame_bundle::encode::TYPE_CONNECTION_FRAME_BUNDLE => {
            authenticate_admission_arm!(
                fact,
                connection::frame_bundle::Codec,
                connection::frame_bundle::authenticate::ConnectionFrameBundleAuthenticator
            )
        }
        connection::frame_observation::encode::TYPE_CONNECTION_FRAME_OBSERVATION => {
            authenticate_admission_arm!(
                fact,
                connection::frame_observation::Codec,
                connection::frame_observation::authenticate::ConnectionFrameObservationAuthenticator
            )
        }
        connection::fact_receipt::encode::TYPE_CONNECTION_FACT_RECEIPT => {
            authenticate_admission_arm!(
                fact,
                connection::fact_receipt::Codec,
                connection::fact_receipt::authenticate::ConnectionFactReceiptAuthenticator
            )
        }
        auth::user_invite::encode::TYPE_USER_INVITE => authenticate_admission_arm!(
            fact,
            auth::user_invite::Codec,
            auth::user_invite::authenticate::UserInviteAuthenticator
        ),
        auth::user::encode::TYPE_USER => authenticate_admission_arm!(
            fact,
            auth::user::Codec,
            auth::user::authenticate::UserAuthenticator
        ),
        _ => Err(format!("no admission route registered for fact tag {tag}")),
    }
}

const FACT_REPLAY_TABLES: &[TableName] = &[
    read_models::OPENED_MESSAGE_ROWS,
    read_models::MESSAGE_TOMBSTONE_ROWS,
    read_models::FILE_SLICE_ROWS,
    auth::workspace::WORKSPACE_ROWS,
    auth::key_wrap::KEY_WRAP_ROWS,
    auth::user::USER_ROWS,
    auth::endpoint::LOCAL_ENDPOINT_ROWS,
    auth::endpoint::LOCAL_ENDPOINT_SECRET_ROWS,
    auth::endpoint::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
    auth::endpoint::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS,
    auth::endpoint_shared::ENDPOINT_SHARED_ROWS,
    auth::admin::ADMIN_ROWS,
    read_models::CONTENT_MESSAGE_ROWS,
    read_models::REACTION_ROWS,
    read_models::FILE_ROWS,
    connection::ephemeral_secret::CONNECTION_EPHEMERAL_SECRET_ROWS,
    connection::fact_receipt::CONNECTION_FACT_RECEIPT_ROWS,
    connection::request::BOOTSTRAP_CONNECTION_ATTEMPT_ROWS,
    connection::request::CONNECTION_REQUEST_ROWS,
    connection::connection::CONNECTION_ROWS,
    auth::invite_accepted::INVITE_ACCEPTED_ROWS,
    auth::invite_server::INVITE_SERVER_ROWS,
    auth::user_invite::USER_INVITE_ROWS,
    auth::device_invite::DEVICE_INVITE_ROWS,
    auth::invite::INVITE_SECRET_ROWS,
    sync::compare::SYNC_COMPARE_ROWS,
    sync::have_id::SYNC_HAVE_ID_ROWS,
    sync::need_id::SYNC_NEED_ID_ROWS,
    sync::shared_fact::index::SHAREABLE_FACT_ROWS,
    sync::shared_fact::index::NEGENTROPY_LEAF_ROWS,
    sync::shared_fact::index::NEGENTROPY_CONTEXT_HAVE_ROWS,
    sync::shared_fact::index::NEGENTROPY_NODE_ROWS,
    read_models::MESSAGE_DELETION_ROWS,
    read_models::FILE_DELETION_ROWS,
    content::retention_policy::RETENTION_POLICY_ROWS,
];

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
CREATE TABLE IF NOT EXISTS auth_endpoint_shared_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);

CREATE TABLE IF NOT EXISTS admin_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);

CREATE TABLE IF NOT EXISTS content_messages (
    workspace_id BLOB NOT NULL,
    message_id BLOB NOT NULL,
    author_user_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    signer_id BLOB NOT NULL,
    frontier_id BLOB NOT NULL,
    minute INTEGER NOT NULL,
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
CREATE TABLE IF NOT EXISTS bootstrap_connection_attempt_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS connection_request_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS connection_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS invite_accepted_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS invite_server_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS user_invite_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS device_invite_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS invite_secret_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sync_compare_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sync_have_id_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sync_need_id_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sync_shareable_fact_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sync_negentropy_leaf_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sync_negentropy_context_have_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sync_negentropy_node_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS connection_fact_receipt_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);

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

CREATE TABLE IF NOT EXISTS retention_policy_rows (row_key BLOB PRIMARY KEY NOT NULL, row_value BLOB NOT NULL);
"#,
    row_tables: &[
        auth::key_wrap::KEY_WRAP_ROWS,
        auth::user::USER_ROWS,
        auth::endpoint::LOCAL_ENDPOINT_ROWS,
        auth::endpoint::LOCAL_ENDPOINT_SECRET_ROWS,
        auth::endpoint::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
        auth::endpoint::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS,
        auth::endpoint_shared::ENDPOINT_SHARED_ROWS,
        auth::admin::ADMIN_ROWS,
        connection::ephemeral_secret::CONNECTION_EPHEMERAL_SECRET_ROWS,
        connection::fact_receipt::CONNECTION_FACT_RECEIPT_ROWS,
        connection::request::BOOTSTRAP_CONNECTION_ATTEMPT_ROWS,
        connection::request::CONNECTION_REQUEST_ROWS,
        connection::connection::CONNECTION_ROWS,
        auth::invite_accepted::INVITE_ACCEPTED_ROWS,
        auth::invite_server::INVITE_SERVER_ROWS,
        auth::user_invite::USER_INVITE_ROWS,
        auth::device_invite::DEVICE_INVITE_ROWS,
        auth::invite::INVITE_SECRET_ROWS,
        sync::compare::SYNC_COMPARE_ROWS,
        sync::have_id::SYNC_HAVE_ID_ROWS,
        sync::need_id::SYNC_NEED_ID_ROWS,
        sync::shared_fact::index::SHAREABLE_FACT_ROWS,
        sync::shared_fact::index::NEGENTROPY_LEAF_ROWS,
        sync::shared_fact::index::NEGENTROPY_CONTEXT_HAVE_ROWS,
        sync::shared_fact::index::NEGENTROPY_NODE_ROWS,
        content::retention_policy::RETENTION_POLICY_ROWS,
    ],
    row_schemas: &[
        auth::workspace::WORKSPACE_ROW_SCHEMA,
        auth::admin::ADMIN_ROW_SCHEMA,
        auth::device_invite::DEVICE_INVITE_ROW_SCHEMA,
        auth::user::USER_ROW_SCHEMA,
        auth::user_invite::USER_INVITE_ROW_SCHEMA,
        auth::invite::INVITE_SECRET_ROW_SCHEMA,
        auth::invite_server::INVITE_SERVER_ROW_SCHEMA,
        auth::invite_accepted::INVITE_ACCEPTED_ROW_SCHEMA,
        auth::endpoint_shared::ENDPOINT_SHARED_ROW_SCHEMA,
        auth::key_wrap::KEY_WRAP_ROW_SCHEMA,
        connection::ephemeral_secret::CONNECTION_EPHEMERAL_SECRET_ROW_SCHEMA,
        connection::fact_receipt::CONNECTION_FACT_RECEIPT_ROW_SCHEMA,
        connection::request::BOOTSTRAP_CONNECTION_ATTEMPT_ROW_SCHEMA,
        connection::request::CONNECTION_REQUEST_ROW_SCHEMA,
        connection::connection::CONNECTION_ROW_SCHEMA,
        sync::compare::SYNC_COMPARE_ROW_SCHEMA,
        sync::have_id::SYNC_HAVE_ID_ROW_SCHEMA,
        sync::need_id::SYNC_NEED_ID_ROW_SCHEMA,
        content::retention_policy::RETENTION_POLICY_ROW_SCHEMA,
    ],
    replay: ReplayTables {
        protected: &[],
        reset: FACT_REPLAY_TABLES,
        summary: FACT_REPLAY_TABLES,
    },
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
        auth::workspace::cli::CREATE_WORKSPACE_USAGE,
        create_workspace
    ),
    cli_command!("invite", auth::invite::cli::INVITE_USAGE, invite),
    cli_command!(
        "invite-server",
        auth::invite::cli::INVITE_SERVER_USAGE,
        invite_server
    ),
    cli_command!("accept", auth::invite::cli::ACCEPT_USAGE, accept),
    cli_command!(
        "connect",
        connection::request::commands::CONNECT_USAGE,
        connect
    ),
    cli_command!(
        "accept-invite-server",
        auth::invite::cli::ACCEPT_INVITE_SERVER_USAGE,
        accept_invite_server
    ),
    cli_command!("link", auth::invite::cli::LINK_USAGE, link),
    cli_command!(
        "accept-link",
        auth::invite::cli::ACCEPT_LINK_USAGE,
        accept_link
    ),
    cli_command!(
        "identity",
        auth::endpoint_shared::cli::IDENTITY_USAGE,
        identity
    ),
    cli_command!("peers", auth::endpoint_shared::cli::PEERS_USAGE, peers),
    cli_command!(
        "workspaces",
        auth::workspace::cli::WORKSPACES_USAGE,
        workspaces
    ),
    cli_command!("users", auth::user::cli::USERS_USAGE, users),
    cli_command!(
        "key-recipient",
        auth::key_wrap::cli::KEY_RECIPIENT_USAGE,
        key_recipient
    ),
    cli_command!(
        "key-rotate-recipient",
        auth::key_wrap::cli::KEY_ROTATE_RECIPIENT_USAGE,
        key_recipient_rotation
    ),
    cli_command!(
        "key-frontier",
        auth::key_wrap::cli::KEY_FRONTIER_USAGE,
        key_frontier
    ),
    cli_command!("key-wrap", auth::key_wrap::cli::KEY_WRAP_USAGE, key_wrap),
    cli_command!(
        "key-access",
        auth::key_wrap::cli::KEY_ACCESS_USAGE,
        key_access
    ),
    cli_command!(
        "key-derive",
        auth::key_wrap::cli::KEY_DERIVE_USAGE,
        key_derive
    ),
    cli_command!("key-node", auth::key_wrap::cli::KEY_NODE_USAGE, key_node),
    cli_command!("keys", auth::key_wrap::cli::KEYS_USAGE, keys),
    cli_command!("chop-now", auth::key_wrap::cli::CHOP_NOW_USAGE, chop_now),
    cli_command!(
        "disappearing-set",
        content::retention_policy::cli::DISAPPEARING_SET_USAGE,
        disappearing_set
    ),
    cli_command!(
        "disappearing-status",
        content::retention_policy::cli::DISAPPEARING_STATUS_USAGE,
        disappearing_status
    ),
    cli_command!(
        "disappearing-tighten",
        content::retention_policy::cli::DISAPPEARING_TIGHTEN_USAGE,
        disappearing_tighten
    ),
    cli_command!(
        "disappearing-compact",
        content::retention_policy::cli::DISAPPEARING_COMPACT_USAGE,
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
        auth::admin::cli::GRANT_ADMIN_USAGE,
        grant_admin
    ),
    cli_command!("generate", content::message::cli::GENERATE_USAGE, generate),
    cli_command!(
        "sync-status",
        sync::shared_fact::cli::SYNC_STATUS_USAGE,
        sync_status
    ),
    cli_command!(
        "sync-range",
        sync::shared_fact::cli::SYNC_RANGE_USAGE,
        sync_range
    ),
    cli_command!(
        "content-count",
        content::message::cli::CONTENT_COUNT_USAGE,
        content_count
    ),
    cli_command!("clock", crate::core::clock::CLOCK_USAGE, clock),
    cli_command!("count", auth::workspace::cli::COUNT_USAGE, count),
    // Replay diagnostics: rebuild derived state, hash replay-relevant state, and
    // prove replay idempotence/order-independence on scratch copies.
    cli_command!("replay", command::REPLAY_USAGE, replay),
    cli_command!("state-summary", command::STATE_SUMMARY_USAGE, state_summary),
    cli_command!("replay-check", command::REPLAY_CHECK_USAGE, replay_check),
    cli_command!(
        "intent-registry",
        command::INTENT_REGISTRY_USAGE,
        intent_registry
    ),
];

pub(crate) const COMMAND_EXCLUDED_HANDLER_ROUTES: &[&str] = &[
    "send_facts_on_connection",
    "send_network_frame",
    "receive_network_frame",
];

pub(crate) const SCHEMA_SOURCES: &[SchemaSource] = &[network::SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE];

pub(crate) const ROW_MUTATION_TABLES: &[TableName] = &[
    connection::ephemeral_secret::CONNECTION_EPHEMERAL_SECRET_ROWS,
    connection::fact_receipt::CONNECTION_FACT_RECEIPT_ROWS,
    connection::request::BOOTSTRAP_CONNECTION_ATTEMPT_ROWS,
    connection::request::CONNECTION_REQUEST_ROWS,
    connection::connection::CONNECTION_ROWS,
    read_models::FILE_ROWS,
    read_models::FILE_DELETION_ROWS,
    read_models::FILE_SLICE_ROWS,
    read_models::CONTENT_MESSAGE_ROWS,
    read_models::MESSAGE_DELETION_ROWS,
    read_models::REACTION_ROWS,
    content::retention_policy::RETENTION_POLICY_ROWS,
    auth::key_wrap::KEY_WRAP_ROWS,
    auth::admin::ADMIN_ROWS,
    auth::device_invite::DEVICE_INVITE_ROWS,
    auth::endpoint::LOCAL_ENDPOINT_ROWS,
    auth::endpoint::LOCAL_ENDPOINT_SECRET_ROWS,
    auth::endpoint::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
    auth::endpoint::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS,
    auth::endpoint_shared::ENDPOINT_SHARED_ROWS,
    auth::invite::INVITE_SECRET_ROWS,
    auth::invite_accepted::INVITE_ACCEPTED_ROWS,
    auth::invite_server::INVITE_SERVER_ROWS,
    auth::user::USER_ROWS,
    auth::user_invite::USER_INVITE_ROWS,
    auth::workspace::WORKSPACE_ROWS,
    read_models::OPENED_MESSAGE_ROWS,
    read_models::MESSAGE_TOMBSTONE_ROWS,
    sync::compare::SYNC_COMPARE_ROWS,
    sync::have_id::SYNC_HAVE_ID_ROWS,
    sync::need_id::SYNC_NEED_ID_ROWS,
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
        RouterProjector::new(FACT_ROUTES, &[]).project(fact, context)
    }
}

// Every fact route is staged: the generated route fn calls the family projector,
// whose `project` routes through core `project_staged`
// (decode -> authenticate -> adapt -> project). The route's staged pipeline
// labels come from the family's `project::PIPELINE` const so a reviewer can line
// up the route declaration with the role files.
macro_rules! projector_route {
    ($name:ident, $projector:path) => {
        fn $name(fact: &Fact, context: &ProjectionContext) -> Result<ProjectionOutput, String> {
            <$projector>::new().project(fact, context)
        }
    };
}

// Projection replay policy is owned by each projector through
// `ProjectionContext::is_replay()`. The route table only names tag routing and
// the first-class staged pipeline labels.
macro_rules! projector_routes {
    ($($name:ident => $tag:path, $projector:path, $pipeline:path ;)+) => {
        $(projector_route!($name, $projector);)+

        pub(crate) const FACT_ROUTES: &[FactRoute] = &[
            $(FactRoute {
                tag: $tag,
                projector: $name,
                pipeline: $pipeline,
            },)+
        ];
    };
}

projector_routes! {
    project_connection_close => connection::close::encode::TYPE_CONNECTION_CLOSE, connection::close::project::ConnectionCloseProjector, connection::close::project::PIPELINE;
    project_connection_ephemeral_secret => connection::ephemeral_secret::encode::TYPE_CONNECTION_EPHEMERAL_SECRET, connection::ephemeral_secret::project::ConnectionEphemeralSecretProjector, connection::ephemeral_secret::project::PIPELINE;
    project_connection_request => connection::request::encode::TYPE_CONNECTION_REQUEST, connection::request::project::ConnectionRequestProjector, connection::request::project::PIPELINE;
    project_connection => connection::connection::encode::TYPE_CONNECTION, connection::connection::project::ConnectionProjector, connection::connection::project::PIPELINE;
    project_content_file => content::file::encode::TYPE_CONTENT_FILE, content::file::project::ContentFileProjector, content::file::project::PIPELINE;
    project_content_file_deletion => content::file_deletion::encode::TYPE_CONTENT_FILE_DELETION, content::file_deletion::project::ContentFileDeletionProjector, content::file_deletion::project::PIPELINE;
    project_content_file_slice => content::file_slice::encode::TYPE_CONTENT_FILE_SLICE, content::file_slice::project::ContentFileSliceProjector, content::file_slice::project::PIPELINE;
    project_content_message => content::message::encode::TYPE_CONTENT_MESSAGE, content::message::project::ContentMessageProjector, content::message::project::PIPELINE;
    project_content_message_deletion => content::message_deletion::encode::TYPE_CONTENT_MESSAGE_DELETION, content::message_deletion::project::ContentMessageDeletionProjector, content::message_deletion::project::PIPELINE;
    project_content_reaction => content::reaction::encode::TYPE_CONTENT_REACTION, content::reaction::project::ContentReactionProjector, content::reaction::project::PIPELINE;
    project_auth_signature => auth::signature::encode::TYPE_SIGNATURE, auth::signature::project::SignatureProjector, auth::signature::project::PIPELINE;
    project_auth_recipient_key => auth::recipient_key::encode::TYPE_RECIPIENT_KEY, auth::recipient_key::project::RecipientKeyProjector, auth::recipient_key::project::PIPELINE;
    project_auth_removal_frontier => auth::removal_frontier::encode::TYPE_REMOVAL_FRONTIER, auth::removal_frontier::project::RemovalFrontierProjector, auth::removal_frontier::project::PIPELINE;
    project_auth_local_key_secret => auth::local_key_secret::encode::TYPE_LOCAL_KEY_SECRET, auth::local_key_secret::project::LocalKeySecretProjector, auth::local_key_secret::project::PIPELINE;
    project_auth_local_history_node_secret => auth::local_history_node_secret::encode::TYPE_LOCAL_HISTORY_NODE_SECRET, auth::local_history_node_secret::project::LocalHistoryNodeSecretProjector, auth::local_history_node_secret::project::PIPELINE;
    project_auth_local_secret_retirement => auth::local_secret_retirement::encode::TYPE_LOCAL_SECRET_RETIREMENT, auth::local_secret_retirement::project::LocalSecretRetirementProjector, auth::local_secret_retirement::project::PIPELINE;
    project_auth_key_request => auth::key_request::encode::TYPE_KEY_REQUEST, auth::key_request::project::KeyRequestProjector, auth::key_request::project::PIPELINE;
    project_auth_key_wrap => auth::key_wrap::encode::TYPE_KEY_WRAP, auth::key_wrap::project::KeyWrapProjector, auth::key_wrap::project::PIPELINE;
    project_auth_local_recipient_key => auth::local_recipient_key::encode::TYPE_LOCAL_RECIPIENT_KEY, auth::local_recipient_key::project::LocalRecipientKeyProjector, auth::local_recipient_key::project::PIPELINE;
    project_endpoint => auth::endpoint::encode::TYPE_LOCAL_ENDPOINT, auth::endpoint::project::EndpointProjector, auth::endpoint::project::PIPELINE;
    project_invite => auth::invite::encode::TYPE_INVITE_SECRET, auth::invite::project::InviteSecretProjector, auth::invite::project::PIPELINE;
    project_workspace => auth::workspace::encode::TYPE_WORKSPACE, auth::workspace::project::WorkspaceProjector, auth::workspace::project::PIPELINE;
    project_auth_local_signer_secret => auth::local_signer_secret::encode::TYPE_LOCAL_SIGNER_SECRET, auth::local_signer_secret::project::LocalSignerSecretProjector, auth::local_signer_secret::project::PIPELINE;
    project_device_invite => auth::device_invite::encode::TYPE_DEVICE_INVITE, auth::device_invite::project::DeviceInviteProjector, auth::device_invite::project::PIPELINE;
    project_endpoint_shared => auth::endpoint_shared::encode::TYPE_ENDPOINT_SHARED, auth::endpoint_shared::project::EndpointSharedProjector, auth::endpoint_shared::project::PIPELINE;
    project_invite_server => auth::invite_server::encode::TYPE_INVITE_SERVER, auth::invite_server::project::InviteServerProjector, auth::invite_server::project::PIPELINE;
    project_admin => auth::admin::encode::TYPE_ADMIN, auth::admin::project::AdminProjector, auth::admin::project::PIPELINE;
    project_invite_accepted => auth::invite_accepted::encode::TYPE_INVITE_ACCEPTED, auth::invite_accepted::project::InviteAcceptedProjector, auth::invite_accepted::project::PIPELINE;
    project_retention_policy => content::retention_policy::encode::TYPE_RETENTION_POLICY, content::retention_policy::project::RetentionPolicyProjector, content::retention_policy::project::PIPELINE;
    project_sync_range_request => sync::range_request::encode::TYPE_SYNC_RANGE_REQUEST, sync::range_request::project::SyncRangeRequestProjector, sync::range_request::project::PIPELINE;
    project_sync_shared_fact => sync::shared_fact::encode::TYPE_SHARED_FACT, sync::shared_fact::project::SyncSharedFactProjector, sync::shared_fact::project::PIPELINE;
    project_sync_compare => sync::compare::encode::TYPE_SYNC_COMPARE, sync::compare::project::SyncCompareProjector, sync::compare::project::PIPELINE;
    project_sync_have_id => sync::have_id::encode::TYPE_SYNC_HAVE_ID, sync::have_id::project::SyncHaveIdProjector, sync::have_id::project::PIPELINE;
    project_sync_need_id => sync::need_id::encode::TYPE_SYNC_NEED_ID, sync::need_id::project::SyncNeedIdProjector, sync::need_id::project::PIPELINE;
    project_connection_frame_small => connection::frame_small::encode::TYPE_CONNECTION_FRAME_SMALL, connection::frame_small::project::ConnectionFrameSmallProjector, connection::frame_small::project::PIPELINE;
    project_connection_frame_file_slice => connection::frame_file_slice::encode::TYPE_CONNECTION_FRAME_FILE_SLICE, connection::frame_file_slice::project::ConnectionFrameFileSliceProjector, connection::frame_file_slice::project::PIPELINE;
    project_connection_frame_bundle => connection::frame_bundle::encode::TYPE_CONNECTION_FRAME_BUNDLE, connection::frame_bundle::project::ConnectionFrameBundleProjector, connection::frame_bundle::project::PIPELINE;
    project_connection_frame_observation => connection::frame_observation::encode::TYPE_CONNECTION_FRAME_OBSERVATION, connection::frame_observation::project::ConnectionFrameObservationProjector, connection::frame_observation::project::PIPELINE;
    project_connection_fact_receipt => connection::fact_receipt::encode::TYPE_CONNECTION_FACT_RECEIPT, connection::fact_receipt::project::ConnectionFactReceiptProjector, connection::fact_receipt::project::PIPELINE;
    project_user_invite => auth::user_invite::encode::TYPE_USER_INVITE, auth::user_invite::project::UserInviteProjector, auth::user_invite::project::PIPELINE;
    project_user => auth::user::encode::TYPE_USER, auth::user::project::UserProjector, auth::user::project::PIPELINE;
}

// Every route must declare `replay = <bool>`: whether core may dispatch this
// intent while replay rebuilds state before the network barrier. The decision
// is mandatory at the macro level so adding a route forces a conscious replay
// classification. `recurring = <RecurringIntentSpec>` marks a live-only
// operational loop the daemon installs as an in-memory schedule after replay.
macro_rules! handler_route {
    ($name:literal, $intent_kind:path, $handler:path, replay = $replay:expr) => {
        HandlerRoute {
            name: $name,
            intent_kind: $intent_kind,
            factory: || Box::new(<$handler>::new()),
            runs_during_replay: $replay,
            recurrence: None,
        }
    };
    ($name:literal, $intent_kind:path, $handler:path, replay = $replay:expr, recurring = $spec:expr) => {
        HandlerRoute {
            name: $name,
            intent_kind: $intent_kind,
            factory: || Box::new(<$handler>::new()),
            runs_during_replay: $replay,
            recurrence: Some($spec),
        }
    };
}

// Replay classification follows the policy in
// docs/research/poc10-replay-intent-shape.md:
//   - Deterministic fact/row rebuild over retained facts runs during replay.
//   - Live session work, send packaging, and network IO do not; that work is
//     rebuilt from committed facts after the replay/network barrier.
pub(crate) const HANDLER_ROUTES: &[HandlerRoute] = &[
    // Handshake/sync sends and the response builders are operational IO over a
    // live session, rebuilt from committed request/response facts after the
    // barrier — never replay-time work.
    handler_route!(
        "create_connection",
        connection::create_connection::CREATE_CONNECTION,
        connection::create_connection::CreateConnectionHandler,
        replay = false
    ),
    handler_route!(
        "send_sync_compare_response",
        sync::send_compare_response::SEND_SYNC_COMPARE_RESPONSE,
        sync::send_compare_response::SendSyncCompareResponseHandler,
        replay = false
    ),
    handler_route!(
        "send_needed_fact_id",
        sync::send_needed_fact_id::SEND_NEEDED_FACT_ID,
        sync::send_needed_fact_id::SendNeededFactIdHandler,
        replay = false
    ),
    handler_route!(
        "send_requested_fact",
        sync::send_requested_fact::SEND_REQUESTED_FACT,
        sync::send_requested_fact::SendRequestedFactHandler,
        replay = false
    ),
    // share_fact_with_sync rebuilds sync-derived shareable/negentropy state from
    // retained facts: deterministic replay rebuild work.
    handler_route!(
        "share_fact_with_sync",
        sync::share_fact_with_sync::SHARE_FACT_WITH_SYNC,
        sync::share_fact_with_sync::ShareFactWithSyncHandler,
        replay = true
    ),
    // Seeding sync runs only for connections explicitly recreated after replay.
    handler_route!(
        "seed_connection_sync",
        sync::seed_connection::SEED_CONNECTION_SYNC,
        sync::seed_connection::SeedConnectionSyncHandler,
        replay = false
    ),
    // Connection maintenance is a live-only recurring operational loop. The
    // daemon installs it as an in-memory schedule and fires it on a fixed
    // cadence; it re-sends unanswered local outbound requests and never runs
    // during replay. This replaces the wall-clock connection_peer_retry wake.
    handler_route!(
        "maintain_connections",
        connection::maintain_connections::MAINTAIN_CONNECTIONS,
        connection::maintain_connections::MaintainConnectionsHandler,
        replay = false,
        recurring = RecurringIntentSpec {
            interval_ms: 250,
            initial_delay_ms: 0,
            build_intent: connection::maintain_connections::build_maintain_connections_intent,
        }
    ),
    // Key wrap creation is deterministic, idempotent fact creation from retained
    // recipient/request/source/signer facts.
    handler_route!(
        "create_key_wrap",
        auth::create_key_wrap::CREATE_KEY_WRAP,
        auth::create_key_wrap::CreateKeyWrapHandler,
        replay = true
    ),
    // Unwrap deterministically creates local secret facts (ids, not plaintext)
    // from retained wrap/recipient/frontier/local recipient-key facts.
    handler_route!(
        "unwrap_key_wrap",
        auth::unwrap_key_wrap::UNWRAP_KEY_WRAP,
        auth::unwrap_key_wrap::UnwrapKeyWrapHandler,
        replay = true
    ),
    // Sending facts over a connection, frame send, and frame receive are
    // operational IO over a live session.
    handler_route!(
        "send_facts_on_connection",
        connection::send_facts_on_connection::SEND_FACTS_ON_CONNECTION,
        connection::send_facts_on_connection::SendFactsOnConnectionHandler,
        replay = false
    ),
    handler_route!(
        "send_network_frame",
        connection::send_network_frame::SEND_NETWORK_FRAME,
        connection::send_network_frame::SendNetworkFrameHandler,
        replay = false
    ),
    handler_route!(
        "receive_network_frame",
        connection::receive_network_frame::RECEIVE_NETWORK_FRAME,
        connection::receive_network_frame::ReceiveNetworkFrameHandler,
        replay = false
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
