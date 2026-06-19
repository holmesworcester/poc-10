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
//! and commands. Intent modules own payloads, handler keys, and handlers.
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
use crate::core::db::{ReplayTables, SchemaSource, StorageVersionSource, TableName};
use crate::core::facts::Fact;
use crate::core::intents::TypedTableSchema;
use crate::core::network;
use crate::core::project_fact::{
    FactRoute, ProjectionContext, ProjectionOutput, Projector, RouterProjector,
};
use crate::core::runtime::{HandlerRoute, RecurringIntentSpec};
use crate::protocol::cli as command;
use crate::protocol::{auth, connection, content, sync, versioning};

pub use crate::protocol::cli::ContextCliContext;

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
    ($fact:expr, $decode:path, $authenticate:path) => {{
        let decoded = $decode($fact.body())?;
        $authenticate($fact, decoded, &ProjectionContext::default()).map(|_| ())
    }};
}

macro_rules! authenticate_sealed_admission_arm {
    ($fact:expr, $validate:path, $authenticate:path) => {{
        $validate($fact.body())?;
        $authenticate($fact, &ProjectionContext::default()).map(|_| ())
    }};
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
            connection::close::project::decode::decode_fact,
            connection::close::project::authenticate::authenticate
        ),
        connection::ephemeral_secret::encode::TYPE_CONNECTION_EPHEMERAL_SECRET => {
            authenticate_admission_arm!(
                fact,
                connection::ephemeral_secret::project::decode::decode_fact,
                connection::ephemeral_secret::project::authenticate::authenticate
            )
        }
        connection::request::encode::TYPE_CONNECTION_REQUEST => authenticate_sealed_admission_arm!(
            fact,
            connection::request::project::decode::validate_sealed_fact,
            connection::request::project::authenticate::authenticate
        ),
        connection::connection::encode::TYPE_CONNECTION => authenticate_sealed_admission_arm!(
            fact,
            connection::connection::project::decode::validate_sealed_fact,
            connection::connection::project::authenticate::authenticate
        ),
        content::file::encode::TYPE_CONTENT_FILE => authenticate_admission_arm!(
            fact,
            content::file::project::decode::decode_fact,
            content::file::project::authenticate::authenticate
        ),
        content::file_deletion::encode::TYPE_CONTENT_FILE_DELETION => authenticate_admission_arm!(
            fact,
            content::file_deletion::project::decode::decode_fact,
            content::file_deletion::project::authenticate::authenticate
        ),
        content::file_slice::encode::TYPE_CONTENT_FILE_SLICE => authenticate_admission_arm!(
            fact,
            content::file_slice::project::decode::decode_fact,
            content::file_slice::project::authenticate::authenticate
        ),
        content::message::encode::TYPE_CONTENT_MESSAGE => authenticate_admission_arm!(
            fact,
            content::message::project::decode::decode_fact,
            content::message::project::authenticate::authenticate
        ),
        content::message_deletion::encode::TYPE_CONTENT_MESSAGE_DELETION => {
            authenticate_admission_arm!(
                fact,
                content::message_deletion::project::decode::decode_fact,
                content::message_deletion::project::authenticate::authenticate
            )
        }
        content::reaction::encode::TYPE_CONTENT_REACTION => authenticate_admission_arm!(
            fact,
            content::reaction::project::decode::decode_fact,
            content::reaction::project::authenticate::authenticate
        ),
        auth::signature::encode::TYPE_SIGNATURE => authenticate_admission_arm!(
            fact,
            auth::signature::project::decode::decode_fact,
            auth::signature::project::authenticate::authenticate
        ),
        auth::recipient_key::encode::TYPE_RECIPIENT_KEY => authenticate_admission_arm!(
            fact,
            auth::recipient_key::project::decode::decode_recipient_key,
            auth::recipient_key::project::authenticate::authenticate
        ),
        auth::removal_frontier::encode::TYPE_REMOVAL_FRONTIER => authenticate_admission_arm!(
            fact,
            auth::removal_frontier::project::decode::decode_removal_frontier,
            auth::removal_frontier::project::authenticate::authenticate
        ),
        auth::local_key_secret::encode::TYPE_LOCAL_KEY_SECRET => authenticate_admission_arm!(
            fact,
            auth::local_key_secret::project::decode::decode_local_key_secret,
            auth::local_key_secret::project::authenticate::authenticate
        ),
        auth::local_history_node_secret::encode::TYPE_LOCAL_HISTORY_NODE_SECRET => {
            authenticate_admission_arm!(
                fact,
                auth::local_history_node_secret::project::decode::decode_local_history_node_secret,
                auth::local_history_node_secret::project::authenticate::authenticate
            )
        }
        auth::local_secret_retirement::encode::TYPE_LOCAL_SECRET_RETIREMENT => {
            authenticate_admission_arm!(
                fact,
                auth::local_secret_retirement::project::decode::decode_fact,
                auth::local_secret_retirement::project::authenticate::authenticate
            )
        }
        auth::key_request::encode::TYPE_KEY_REQUEST => authenticate_admission_arm!(
            fact,
            auth::key_request::project::decode::decode_key_request,
            auth::key_request::project::authenticate::authenticate
        ),
        auth::key_wrap::encode::TYPE_KEY_WRAP => authenticate_admission_arm!(
            fact,
            auth::key_wrap::project::decode::decode_key_wrap,
            auth::key_wrap::project::authenticate::authenticate
        ),
        auth::key_wrap_creation::encode::TYPE_KEY_WRAP_CREATION => authenticate_admission_arm!(
            fact,
            auth::key_wrap_creation::project::decode::decode_fact,
            auth::key_wrap_creation::project::authenticate::authenticate
        ),
        auth::key_wrap_recovery::encode::TYPE_KEY_WRAP_RECOVERY => authenticate_admission_arm!(
            fact,
            auth::key_wrap_recovery::project::decode::decode_fact,
            auth::key_wrap_recovery::project::authenticate::authenticate
        ),
        auth::local_recipient_key::encode::TYPE_LOCAL_RECIPIENT_KEY => {
            authenticate_admission_arm!(
                fact,
                auth::local_recipient_key::project::decode::decode_local_recipient_key,
                auth::local_recipient_key::project::authenticate::authenticate
            )
        }
        auth::endpoint::encode::TYPE_LOCAL_ENDPOINT => authenticate_admission_arm!(
            fact,
            auth::endpoint::project::decode::decode_fact,
            auth::endpoint::project::authenticate::authenticate
        ),
        auth::invite_secret::encode::TYPE_INVITE_SECRET => authenticate_admission_arm!(
            fact,
            auth::invite_secret::project::decode::decode_fact,
            auth::invite_secret::project::authenticate::authenticate
        ),
        auth::workspace::encode::TYPE_WORKSPACE => authenticate_admission_arm!(
            fact,
            auth::workspace::project::decode::decode_fact,
            auth::workspace::project::authenticate::authenticate
        ),
        auth::local_signer_secret::encode::TYPE_LOCAL_SIGNER_SECRET => authenticate_admission_arm!(
            fact,
            auth::local_signer_secret::project::decode::decode_fact,
            auth::local_signer_secret::project::authenticate::authenticate
        ),
        auth::device_invite::encode::TYPE_DEVICE_INVITE => authenticate_admission_arm!(
            fact,
            auth::device_invite::project::decode::decode_fact,
            auth::device_invite::project::authenticate::authenticate
        ),
        auth::endpoint_shared::encode::TYPE_ENDPOINT_SHARED => authenticate_admission_arm!(
            fact,
            auth::endpoint_shared::project::decode::decode_fact,
            auth::endpoint_shared::project::authenticate::authenticate
        ),
        auth::invite_server::encode::TYPE_INVITE_SERVER => authenticate_admission_arm!(
            fact,
            auth::invite_server::project::decode::decode_fact,
            auth::invite_server::project::authenticate::authenticate
        ),
        auth::admin::encode::TYPE_ADMIN => authenticate_admission_arm!(
            fact,
            auth::admin::project::decode::decode_fact,
            auth::admin::project::authenticate::authenticate
        ),
        auth::invite_accepted::encode::TYPE_INVITE_ACCEPTED => authenticate_admission_arm!(
            fact,
            auth::invite_accepted::project::decode::decode_fact,
            auth::invite_accepted::project::authenticate::authenticate
        ),
        content::retention_policy::encode::TYPE_RETENTION_POLICY => authenticate_admission_arm!(
            fact,
            content::retention_policy::project::decode::decode_fact,
            content::retention_policy::project::authenticate::authenticate
        ),
        sync::range_request::encode::TYPE_SYNC_RANGE_REQUEST => authenticate_admission_arm!(
            fact,
            sync::range_request::project::decode::decode_fact,
            sync::range_request::project::authenticate::authenticate
        ),
        sync::shared_fact::encode::TYPE_SHARED_FACT => authenticate_admission_arm!(
            fact,
            sync::shared_fact::project::decode::decode_fact,
            sync::shared_fact::project::authenticate::authenticate
        ),
        sync::compare::encode::TYPE_SYNC_COMPARE => authenticate_admission_arm!(
            fact,
            sync::compare::project::decode::decode_fact,
            sync::compare::project::authenticate::authenticate
        ),
        sync::have_id::encode::TYPE_SYNC_HAVE_ID => authenticate_admission_arm!(
            fact,
            sync::have_id::project::decode::decode_fact,
            sync::have_id::project::authenticate::authenticate
        ),
        sync::need_id::encode::TYPE_SYNC_NEED_ID => authenticate_admission_arm!(
            fact,
            sync::need_id::project::decode::decode_fact,
            sync::need_id::project::authenticate::authenticate
        ),
        sync::local_setting::TYPE_SYNC_LOCAL_SETTING => authenticate_admission_arm!(
            fact,
            sync::local_setting::decode_fact_payload,
            sync::local_setting::authenticate
        ),
        versioning::local_update::encode::TYPE_VERSIONING_UPDATE => authenticate_admission_arm!(
            fact,
            versioning::local_update::encode::decode_update_fact,
            versioning::local_update::project::authenticate
        ),
        connection::frame_small::encode::TYPE_CONNECTION_FRAME_SMALL => {
            authenticate_admission_arm!(
                fact,
                connection::frame_small::project::decode::decode_fact,
                connection::frame_small::project::authenticate::authenticate
            )
        }
        connection::frame_file_slice::encode::TYPE_CONNECTION_FRAME_FILE_SLICE => {
            authenticate_admission_arm!(
                fact,
                connection::frame_file_slice::project::decode::decode_fact,
                connection::frame_file_slice::project::authenticate::authenticate
            )
        }
        connection::frame_bundle::encode::TYPE_CONNECTION_FRAME_BUNDLE => {
            authenticate_admission_arm!(
                fact,
                connection::frame_bundle::project::decode::decode_fact,
                connection::frame_bundle::project::authenticate::authenticate
            )
        }
        connection::frame_observation::encode::TYPE_CONNECTION_FRAME_OBSERVATION => {
            authenticate_admission_arm!(
                fact,
                connection::frame_observation::project::decode::decode_fact,
                connection::frame_observation::project::authenticate::authenticate
            )
        }
        connection::fact_receipt::encode::TYPE_CONNECTION_FACT_RECEIPT => {
            authenticate_admission_arm!(
                fact,
                connection::fact_receipt::project::decode::decode_fact,
                connection::fact_receipt::project::authenticate::authenticate
            )
        }
        auth::user_invite::encode::TYPE_USER_INVITE => authenticate_admission_arm!(
            fact,
            auth::user_invite::project::decode::decode_fact,
            auth::user_invite::project::authenticate::authenticate
        ),
        auth::user::encode::TYPE_USER => authenticate_admission_arm!(
            fact,
            auth::user::project::decode::decode_fact,
            auth::user::project::authenticate::authenticate
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
    auth::local_key_secret::LOCAL_KEY_SECRET_ROWS,
    auth::local_history_node_secret::LOCAL_HISTORY_NODE_SECRET_ROWS,
    auth::local_history_node_secret::LOCAL_HISTORY_NODE_TOMBSTONE_ROWS,
    auth::local_recipient_key::LOCAL_RECIPIENT_KEY_ROWS,
    auth::recipient_key::RECIPIENT_KEY_ROWS,
    auth::removal_frontier::REMOVAL_FRONTIER_ROWS,
    auth::user::USER_ROWS,
    auth::endpoint::LOCAL_ENDPOINT_ROWS,
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
    auth::invite_secret::INVITE_SECRET_ROWS,
    sync::compare::SYNC_COMPARE_ROWS,
    sync::have_id::SYNC_HAVE_ID_ROWS,
    sync::need_id::SYNC_NEED_ID_ROWS,
    sync::shared_fact::index::SHAREABLE_FACT_ROWS,
    sync::shared_fact::index::NEGENTROPY_LEAF_ROWS,
    sync::shared_fact::index::NEGENTROPY_CONTEXT_HAVE_ROWS,
    sync::shared_fact::index::NEGENTROPY_NODE_ROWS,
    sync::local_setting::SYNC_LOCAL_SETTING_ROWS,
    read_models::MESSAGE_DELETION_ROWS,
    read_models::FILE_DELETION_ROWS,
    content::retention_policy::RETENTION_POLICY_ROWS,
];

const FACT_REPLAY_PROTECTED_TABLES: &[TableName] =
    &[versioning::local_update::PROTOCOL_VERSION_ROWS];

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

CREATE TABLE IF NOT EXISTS protocol_version_rows (
    update_fact_id BLOB PRIMARY KEY NOT NULL,
    protocol_version INTEGER NOT NULL,
    applied_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS protocol_version_rows_by_version
    ON protocol_version_rows (protocol_version, applied_at_ms);

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

CREATE TABLE IF NOT EXISTS workspace_rows (
    workspace_id BLOB PRIMARY KEY NOT NULL,
    created_at_ms INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    name BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS key_wrap_rows (
    workspace_id BLOB NOT NULL,
    frontier_id BLOB NOT NULL,
    recipient_key_id BLOB NOT NULL,
    wrapped_secret_kind INTEGER NOT NULL,
    range_start INTEGER NOT NULL,
    range_width INTEGER NOT NULL,
    bit_depth INTEGER NOT NULL,
    fact_id_prefix BLOB NOT NULL,
    key_wrap_id BLOB NOT NULL,
    signer_public_key BLOB NOT NULL,
    wrap BLOB NOT NULL,
    PRIMARY KEY (
        workspace_id,
        frontier_id,
        recipient_key_id,
        wrapped_secret_kind,
        range_start,
        range_width,
        bit_depth,
        fact_id_prefix
    )
);
CREATE TABLE IF NOT EXISTS user_rows (
    workspace_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    user_invite_id BLOB NOT NULL,
    username BLOB NOT NULL,
    PRIMARY KEY (workspace_id, user_id)
);
CREATE TABLE IF NOT EXISTS local_endpoint_rows (
    local_key BLOB PRIMARY KEY NOT NULL,
    endpoint_id BLOB NOT NULL,
    secret BLOB NOT NULL,
    signing_public_key BLOB NOT NULL,
    signing_secret BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_endpoint_shared_rows (
    workspace_id BLOB NOT NULL,
    endpoint_shared_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    endpoint_id BLOB NOT NULL,
    signing_public_key BLOB NOT NULL,
    endpoint_role INTEGER NOT NULL,
    user_authority_fact_id BLOB NOT NULL,
    device_name BLOB NOT NULL,
    PRIMARY KEY (workspace_id, endpoint_shared_id)
);

CREATE TABLE IF NOT EXISTS admin_rows (
    workspace_id BLOB NOT NULL,
    admin_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    authority_fact_id BLOB NOT NULL,
    user_fact_id BLOB NOT NULL,
    PRIMARY KEY (workspace_id, admin_id)
);

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

CREATE TABLE IF NOT EXISTS local_key_secret_rows (
    workspace_id BLOB NOT NULL,
    frontier_id BLOB NOT NULL,
    secret_id BLOB NOT NULL,
    owner_endpoint_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    key_secret BLOB NOT NULL,
    PRIMARY KEY (workspace_id, frontier_id, secret_id)
);
CREATE INDEX IF NOT EXISTS local_key_secret_rows_by_workspace_created
    ON local_key_secret_rows (workspace_id, created_at_ms, frontier_id);

CREATE TABLE IF NOT EXISTS local_history_node_secret_rows (
    workspace_id BLOB NOT NULL,
    frontier_id BLOB NOT NULL,
    secret_id BLOB NOT NULL,
    owner_endpoint_id BLOB NOT NULL,
    source_secret_id BLOB NOT NULL,
    range_start INTEGER NOT NULL,
    range_width INTEGER NOT NULL,
    bit_depth INTEGER NOT NULL,
    fact_id_prefix BLOB NOT NULL,
    tombstone_node_id BLOB NOT NULL,
    node_secret BLOB NOT NULL,
    PRIMARY KEY (workspace_id, frontier_id, secret_id)
);
CREATE INDEX IF NOT EXISTS local_history_node_secret_rows_by_frontier_range
    ON local_history_node_secret_rows (workspace_id, frontier_id, range_start, range_width);

CREATE TABLE IF NOT EXISTS local_history_node_tombstone_rows (
    tombstone_node_id BLOB NOT NULL,
    secret_id BLOB NOT NULL,
    PRIMARY KEY (tombstone_node_id, secret_id)
);
CREATE INDEX IF NOT EXISTS local_history_node_tombstone_rows_by_secret
    ON local_history_node_tombstone_rows (secret_id);

CREATE TABLE IF NOT EXISTS local_recipient_key_rows (
    workspace_id BLOB NOT NULL,
    recipient_key_id BLOB NOT NULL,
    fact_timestamp INTEGER NOT NULL,
    recipient_key BLOB NOT NULL,
    recipient_secret BLOB NOT NULL,
    PRIMARY KEY (workspace_id, recipient_key_id)
);
CREATE INDEX IF NOT EXISTS local_recipient_key_rows_by_workspace_timestamp
    ON local_recipient_key_rows (workspace_id, fact_timestamp, recipient_key_id);

CREATE TABLE IF NOT EXISTS recipient_key_rows (
    workspace_id BLOB NOT NULL,
    recipient_key_id BLOB NOT NULL,
    endpoint_id BLOB NOT NULL,
    recipient_key BLOB NOT NULL,
    previous_recipient_key_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    signer_public_key BLOB NOT NULL,
    PRIMARY KEY (workspace_id, recipient_key_id)
);
CREATE INDEX IF NOT EXISTS recipient_key_rows_by_endpoint
    ON recipient_key_rows (workspace_id, endpoint_id);
CREATE INDEX IF NOT EXISTS recipient_key_rows_by_previous
    ON recipient_key_rows (workspace_id, previous_recipient_key_id);

CREATE TABLE IF NOT EXISTS removal_frontier_rows (
    workspace_id BLOB NOT NULL,
    frontier_id BLOB NOT NULL,
    owner_endpoint_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    signer_public_key BLOB NOT NULL,
    PRIMARY KEY (workspace_id, frontier_id)
);
CREATE TABLE IF NOT EXISTS connection_ephemeral_secret_rows (
    secret_id BLOB PRIMARY KEY NOT NULL,
    owner_endpoint BLOB NOT NULL,
    ephemeral_private_key BLOB NOT NULL,
    ephemeral_public_key BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bootstrap_connection_attempt_rows (
    invite_accepted_fact_id BLOB PRIMARY KEY NOT NULL,
    request_id BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS connection_request_rows (
    request_id BLOB PRIMARY KEY NOT NULL,
    request_sent_id BLOB NOT NULL,
    initiator_ephemeral_secret_fact_id BLOB NOT NULL,
    peer_addr BLOB NOT NULL,
    sealed_request_bytes BLOB NOT NULL
);
CREATE TEMP TABLE IF NOT EXISTS connection_maintenance_rows (
    kind TEXT PRIMARY KEY NOT NULL,
    last_run_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS connection_rows (
    connection_id BLOB PRIMARY KEY NOT NULL,
    from_endpoint BLOB NOT NULL,
    to_endpoint BLOB NOT NULL,
    request_id BLOB NOT NULL,
    responder_ephemeral_public_key BLOB NOT NULL,
    handshake_hash BLOB NOT NULL,
    connection_secret BLOB NOT NULL,
    responder_addr BLOB NOT NULL,
    initiator_addr BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS connection_rows_by_request
    ON connection_rows (request_id);
CREATE TABLE IF NOT EXISTS invite_accepted_rows (
    accepted_endpoint_id BLOB NOT NULL,
    workspace_id BLOB NOT NULL,
    invite_fact_id BLOB NOT NULL,
    invite_accepted_fact_id BLOB NOT NULL,
    bootstrap_hash BLOB NOT NULL,
    bootstrap_secret BLOB NOT NULL,
    bootstrap_endpoint_id BLOB NOT NULL,
    bootstrap_addr BLOB NOT NULL,
    user_authority_fact_id_or_zero BLOB NOT NULL,
    endpoint_role INTEGER NOT NULL,
    identity_scope INTEGER NOT NULL,
    PRIMARY KEY (accepted_endpoint_id, workspace_id, invite_fact_id)
);
CREATE INDEX IF NOT EXISTS invite_accepted_rows_by_bootstrap
    ON invite_accepted_rows (bootstrap_hash, workspace_id, invite_fact_id);

CREATE TABLE IF NOT EXISTS invite_server_rows (
    workspace_id BLOB NOT NULL,
    invite_server_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    authority_fact_id BLOB NOT NULL,
    PRIMARY KEY (workspace_id, invite_server_id)
);

CREATE TABLE IF NOT EXISTS user_invite_rows (
    workspace_id BLOB NOT NULL,
    user_invite_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    authority_fact_id BLOB NOT NULL,
    PRIMARY KEY (workspace_id, user_invite_id)
);

CREATE TABLE IF NOT EXISTS device_invite_rows (
    workspace_id BLOB NOT NULL,
    device_invite_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    user_authority_fact_id BLOB NOT NULL,
    user_invite_fact_id BLOB NOT NULL,
    public_key BLOB NOT NULL,
    PRIMARY KEY (workspace_id, device_invite_id)
);

CREATE TABLE IF NOT EXISTS invite_secret_rows (
    bootstrap_hash BLOB NOT NULL,
    workspace_id_or_zero BLOB NOT NULL,
    invite_fact_id_or_zero BLOB NOT NULL,
    bootstrap_secret BLOB NOT NULL,
    PRIMARY KEY (bootstrap_hash, workspace_id_or_zero, invite_fact_id_or_zero)
);
CREATE TABLE IF NOT EXISTS sync_compare_rows (
    connection_id BLOB NOT NULL,
    fact_id BLOB NOT NULL,
    range_start BLOB NOT NULL,
    range_end BLOB NOT NULL,
    count INTEGER NOT NULL,
    fingerprint BLOB NOT NULL,
    response_requested INTEGER NOT NULL,
    PRIMARY KEY (connection_id, fact_id)
);

CREATE TABLE IF NOT EXISTS sync_have_id_rows (
    connection_id BLOB NOT NULL,
    fact_id BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    advertised_fact_id BLOB NOT NULL,
    PRIMARY KEY (connection_id, fact_id)
);

CREATE TABLE IF NOT EXISTS sync_need_id_rows (
    connection_id BLOB NOT NULL,
    fact_id BLOB NOT NULL,
    requested_fact_id BLOB NOT NULL,
    PRIMARY KEY (connection_id, fact_id)
);
CREATE TABLE IF NOT EXISTS sync_shareable_fact_rows (
    workspace_id BLOB NOT NULL,
    fact_id BLOB NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, fact_id)
);

CREATE TABLE IF NOT EXISTS sync_negentropy_leaf_rows (
    workspace_id BLOB NOT NULL,
    owner_fact_id BLOB NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    contribution_fingerprint BLOB NOT NULL,
    PRIMARY KEY (workspace_id, owner_fact_id)
);

CREATE TABLE IF NOT EXISTS sync_negentropy_context_have_rows (
    workspace_id BLOB NOT NULL,
    owner_fact_id BLOB NOT NULL,
    context_fact_id BLOB NOT NULL,
    PRIMARY KEY (workspace_id, owner_fact_id, context_fact_id)
);

CREATE TABLE IF NOT EXISTS sync_negentropy_context_closure_rows (
    workspace_id BLOB NOT NULL,
    owner_fact_id BLOB NOT NULL,
    context_fact_id BLOB NOT NULL,
    PRIMARY KEY (workspace_id, owner_fact_id, context_fact_id)
);

CREATE TABLE IF NOT EXISTS sync_negentropy_node_rows (
    workspace_id BLOB NOT NULL,
    level INTEGER NOT NULL,
    start_timestamp_ms INTEGER NOT NULL,
    count INTEGER NOT NULL,
    fingerprint BLOB NOT NULL,
    PRIMARY KEY (workspace_id, level, start_timestamp_ms)
);
CREATE TABLE IF NOT EXISTS sync_local_setting_rows (
    setting_fact_id BLOB PRIMARY KEY NOT NULL,
    mode INTEGER NOT NULL,
    effective_at_ms INTEGER NOT NULL,
    start_ms BLOB NOT NULL,
    end_ms BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS sync_local_setting_rows_by_effective
    ON sync_local_setting_rows (effective_at_ms, setting_fact_id);
CREATE TEMP TABLE IF NOT EXISTS sync_maintenance_rows (
    kind TEXT PRIMARY KEY NOT NULL,
    last_run_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS connection_fact_receipt_rows (
    received_fact_id BLOB NOT NULL,
    receipt_fact_id BLOB NOT NULL,
    has_connection INTEGER NOT NULL,
    connection_id BLOB NOT NULL,
    PRIMARY KEY (received_fact_id, receipt_fact_id)
);

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

CREATE TABLE IF NOT EXISTS retention_policy_rows (
    workspace_id BLOB NOT NULL,
    scope_kind INTEGER NOT NULL,
    scope_id BLOB NOT NULL,
    policy_id BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    ttl_minutes INTEGER NOT NULL,
    retire_minute INTEGER NOT NULL,
    author_user_id BLOB NOT NULL,
    supersedes_policy_id BLOB NOT NULL,
    PRIMARY KEY (workspace_id, scope_kind, scope_id, policy_id)
);
"#,
    storage_version: Some(StorageVersionSource {
        table: versioning::local_update::PROTOCOL_VERSION_ROWS,
        version_column: "protocol_version",
        order_by_columns: &["applied_at_ms", "update_fact_id"],
    }),
    replay: ReplayTables {
        protected: FACT_REPLAY_PROTECTED_TABLES,
        reset: FACT_REPLAY_TABLES,
        summary: &[
            versioning::local_update::PROTOCOL_VERSION_ROWS,
            read_models::OPENED_MESSAGE_ROWS,
            read_models::MESSAGE_TOMBSTONE_ROWS,
            read_models::FILE_SLICE_ROWS,
            auth::workspace::WORKSPACE_ROWS,
            auth::key_wrap::KEY_WRAP_ROWS,
            auth::local_key_secret::LOCAL_KEY_SECRET_ROWS,
            auth::local_history_node_secret::LOCAL_HISTORY_NODE_SECRET_ROWS,
            auth::local_history_node_secret::LOCAL_HISTORY_NODE_TOMBSTONE_ROWS,
            auth::local_recipient_key::LOCAL_RECIPIENT_KEY_ROWS,
            auth::recipient_key::RECIPIENT_KEY_ROWS,
            auth::removal_frontier::REMOVAL_FRONTIER_ROWS,
            auth::user::USER_ROWS,
            auth::endpoint::LOCAL_ENDPOINT_ROWS,
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
            auth::invite_secret::INVITE_SECRET_ROWS,
            sync::compare::SYNC_COMPARE_ROWS,
            sync::have_id::SYNC_HAVE_ID_ROWS,
            sync::need_id::SYNC_NEED_ID_ROWS,
            sync::shared_fact::index::SHAREABLE_FACT_ROWS,
            sync::shared_fact::index::NEGENTROPY_LEAF_ROWS,
            sync::shared_fact::index::NEGENTROPY_CONTEXT_HAVE_ROWS,
            sync::shared_fact::index::NEGENTROPY_NODE_ROWS,
            sync::local_setting::SYNC_LOCAL_SETTING_ROWS,
            read_models::MESSAGE_DELETION_ROWS,
            read_models::FILE_DELETION_ROWS,
            content::retention_policy::RETENTION_POLICY_ROWS,
        ],
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

pub const CONTEXT_COMMANDS: &[CliCommand<ContextCliContext>] = &[
    cli_command!(
        "create-workspace",
        auth::workspace::cli::CREATE_WORKSPACE_USAGE,
        create_workspace
    ),
    cli_command!("invite", auth::invite_secret::cli::INVITE_USAGE, invite),
    cli_command!(
        "invite-server",
        auth::invite_secret::cli::INVITE_SERVER_USAGE,
        invite_server
    ),
    cli_command!("accept", auth::invite_secret::cli::ACCEPT_USAGE, accept),
    cli_command!("connect", connection::request::api::CONNECT_USAGE, connect),
    cli_command!(
        "accept-invite-server",
        auth::invite_secret::cli::ACCEPT_INVITE_SERVER_USAGE,
        accept_invite_server
    ),
    cli_command!("link", auth::invite_secret::cli::LINK_USAGE, link),
    cli_command!(
        "accept-link",
        auth::invite_secret::cli::ACCEPT_LINK_USAGE,
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
    cli_command!("sync", sync::local_setting::SYNC_USAGE, sync),
    cli_command!(
        "content-count",
        content::message::cli::CONTENT_COUNT_USAGE,
        content_count
    ),
    cli_command!("count", auth::workspace::cli::COUNT_USAGE, count),
    // Versioning diagnostics: request a local protocol update and hash
    // rebuild-relevant state.
    cli_command!(
        "update",
        versioning::local_update::cli::UPDATE_USAGE,
        update
    ),
    cli_command!(
        "state-summary",
        versioning::local_update::cli::STATE_SUMMARY_USAGE,
        state_summary
    ),
    cli_command!(
        "intent-registry",
        command::INTENT_REGISTRY_USAGE,
        intent_registry
    ),
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
    auth::local_key_secret::LOCAL_KEY_SECRET_ROWS,
    auth::local_history_node_secret::LOCAL_HISTORY_NODE_SECRET_ROWS,
    auth::local_history_node_secret::LOCAL_HISTORY_NODE_TOMBSTONE_ROWS,
    auth::local_recipient_key::LOCAL_RECIPIENT_KEY_ROWS,
    auth::recipient_key::RECIPIENT_KEY_ROWS,
    auth::removal_frontier::REMOVAL_FRONTIER_ROWS,
    auth::admin::ADMIN_ROWS,
    auth::device_invite::DEVICE_INVITE_ROWS,
    auth::endpoint::LOCAL_ENDPOINT_ROWS,
    auth::endpoint_shared::ENDPOINT_SHARED_ROWS,
    auth::invite_secret::INVITE_SECRET_ROWS,
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
    sync::local_setting::SYNC_LOCAL_SETTING_ROWS,
    versioning::local_update::PROTOCOL_VERSION_ROWS,
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

// Every fact route is explicit: the generated route fn calls the family
// projector, whose `project` routes through the protocol-local projector
// (decode -> authenticate -> adapt -> project). The route metadata comes from
// the family's `project::PROJECTOR_INFO` const so a reviewer can line up the
// route declaration with the role files.
macro_rules! projector_route {
    ($name:ident, $projector:path) => {
        fn $name(fact: &Fact, context: &ProjectionContext) -> Result<ProjectionOutput, String> {
            <$projector>::new().project(fact, context)
        }
    };
}

// Projection replay policy is owned by each projector through
// `ProjectionContext::is_replay()`. The route table only names tag routing and
// first-class projector metadata.
macro_rules! projector_routes {
    ($($name:ident => $tag:path, $projector:path, $projector_info:path, $storage_requirement:path ;)+) => {
        $(projector_route!($name, $projector);)+

        pub(crate) const FACT_ROUTES: &[FactRoute] = &[
            $(FactRoute {
                tag: $tag,
                projector: $name,
                storage_requirement: $storage_requirement,
                projector_info: $projector_info,
            },)+
        ];
    };
}

projector_routes! {
    project_connection_close => connection::close::encode::TYPE_CONNECTION_CLOSE, connection::close::project::ConnectionCloseProjector, connection::close::project::PROJECTOR_INFO, connection::close::project::STORAGE_REQUIREMENT;
    project_connection_ephemeral_secret => connection::ephemeral_secret::encode::TYPE_CONNECTION_EPHEMERAL_SECRET, connection::ephemeral_secret::project::ConnectionEphemeralSecretProjector, connection::ephemeral_secret::project::PROJECTOR_INFO, connection::ephemeral_secret::project::STORAGE_REQUIREMENT;
    project_connection_request => connection::request::encode::TYPE_CONNECTION_REQUEST, connection::request::project::ConnectionRequestProjector, connection::request::project::PROJECTOR_INFO, connection::request::project::STORAGE_REQUIREMENT;
    project_connection => connection::connection::encode::TYPE_CONNECTION, connection::connection::project::ConnectionProjector, connection::connection::project::PROJECTOR_INFO, connection::connection::project::STORAGE_REQUIREMENT;
    project_content_file => content::file::encode::TYPE_CONTENT_FILE, content::file::project::ContentFileProjector, content::file::project::PROJECTOR_INFO, content::file::project::STORAGE_REQUIREMENT;
    project_content_file_deletion => content::file_deletion::encode::TYPE_CONTENT_FILE_DELETION, content::file_deletion::project::ContentFileDeletionProjector, content::file_deletion::project::PROJECTOR_INFO, content::file_deletion::project::STORAGE_REQUIREMENT;
    project_content_file_slice => content::file_slice::encode::TYPE_CONTENT_FILE_SLICE, content::file_slice::project::ContentFileSliceProjector, content::file_slice::project::PROJECTOR_INFO, content::file_slice::project::STORAGE_REQUIREMENT;
    project_content_message => content::message::encode::TYPE_CONTENT_MESSAGE, content::message::project::ContentMessageProjector, content::message::project::PROJECTOR_INFO, content::message::project::STORAGE_REQUIREMENT;
    project_content_message_deletion => content::message_deletion::encode::TYPE_CONTENT_MESSAGE_DELETION, content::message_deletion::project::ContentMessageDeletionProjector, content::message_deletion::project::PROJECTOR_INFO, content::message_deletion::project::STORAGE_REQUIREMENT;
    project_content_reaction => content::reaction::encode::TYPE_CONTENT_REACTION, content::reaction::project::ContentReactionProjector, content::reaction::project::PROJECTOR_INFO, content::reaction::project::STORAGE_REQUIREMENT;
    project_auth_signature => auth::signature::encode::TYPE_SIGNATURE, auth::signature::project::SignatureProjector, auth::signature::project::PROJECTOR_INFO, auth::signature::project::STORAGE_REQUIREMENT;
    project_auth_recipient_key => auth::recipient_key::encode::TYPE_RECIPIENT_KEY, auth::recipient_key::project::RecipientKeyProjector, auth::recipient_key::project::PROJECTOR_INFO, auth::recipient_key::project::STORAGE_REQUIREMENT;
    project_auth_removal_frontier => auth::removal_frontier::encode::TYPE_REMOVAL_FRONTIER, auth::removal_frontier::project::RemovalFrontierProjector, auth::removal_frontier::project::PROJECTOR_INFO, auth::removal_frontier::project::STORAGE_REQUIREMENT;
    project_auth_local_key_secret => auth::local_key_secret::encode::TYPE_LOCAL_KEY_SECRET, auth::local_key_secret::project::LocalKeySecretProjector, auth::local_key_secret::project::PROJECTOR_INFO, auth::local_key_secret::project::STORAGE_REQUIREMENT;
    project_auth_local_history_node_secret => auth::local_history_node_secret::encode::TYPE_LOCAL_HISTORY_NODE_SECRET, auth::local_history_node_secret::project::LocalHistoryNodeSecretProjector, auth::local_history_node_secret::project::PROJECTOR_INFO, auth::local_history_node_secret::project::STORAGE_REQUIREMENT;
    project_auth_local_secret_retirement => auth::local_secret_retirement::encode::TYPE_LOCAL_SECRET_RETIREMENT, auth::local_secret_retirement::project::LocalSecretRetirementProjector, auth::local_secret_retirement::project::PROJECTOR_INFO, auth::local_secret_retirement::project::STORAGE_REQUIREMENT;
    project_auth_key_request => auth::key_request::encode::TYPE_KEY_REQUEST, auth::key_request::project::KeyRequestProjector, auth::key_request::project::PROJECTOR_INFO, auth::key_request::project::STORAGE_REQUIREMENT;
    project_auth_key_wrap => auth::key_wrap::encode::TYPE_KEY_WRAP, auth::key_wrap::project::KeyWrapProjector, auth::key_wrap::project::PROJECTOR_INFO, auth::key_wrap::project::STORAGE_REQUIREMENT;
    project_auth_key_wrap_creation => auth::key_wrap_creation::encode::TYPE_KEY_WRAP_CREATION, auth::key_wrap_creation::project::KeyWrapCreationProjector, auth::key_wrap_creation::project::PROJECTOR_INFO, auth::key_wrap_creation::project::STORAGE_REQUIREMENT;
    project_auth_key_wrap_recovery => auth::key_wrap_recovery::encode::TYPE_KEY_WRAP_RECOVERY, auth::key_wrap_recovery::project::KeyWrapRecoveryProjector, auth::key_wrap_recovery::project::PROJECTOR_INFO, auth::key_wrap_recovery::project::STORAGE_REQUIREMENT;
    project_auth_local_recipient_key => auth::local_recipient_key::encode::TYPE_LOCAL_RECIPIENT_KEY, auth::local_recipient_key::project::LocalRecipientKeyProjector, auth::local_recipient_key::project::PROJECTOR_INFO, auth::local_recipient_key::project::STORAGE_REQUIREMENT;
    project_endpoint => auth::endpoint::encode::TYPE_LOCAL_ENDPOINT, auth::endpoint::project::EndpointProjector, auth::endpoint::project::PROJECTOR_INFO, auth::endpoint::project::STORAGE_REQUIREMENT;
    project_invite_secret => auth::invite_secret::encode::TYPE_INVITE_SECRET, auth::invite_secret::project::InviteSecretProjector, auth::invite_secret::project::PROJECTOR_INFO, auth::invite_secret::project::STORAGE_REQUIREMENT;
    project_workspace => auth::workspace::encode::TYPE_WORKSPACE, auth::workspace::project::WorkspaceProjector, auth::workspace::project::PROJECTOR_INFO, auth::workspace::project::STORAGE_REQUIREMENT;
    project_auth_local_signer_secret => auth::local_signer_secret::encode::TYPE_LOCAL_SIGNER_SECRET, auth::local_signer_secret::project::LocalSignerSecretProjector, auth::local_signer_secret::project::PROJECTOR_INFO, auth::local_signer_secret::project::STORAGE_REQUIREMENT;
    project_device_invite => auth::device_invite::encode::TYPE_DEVICE_INVITE, auth::device_invite::project::DeviceInviteProjector, auth::device_invite::project::PROJECTOR_INFO, auth::device_invite::project::STORAGE_REQUIREMENT;
    project_endpoint_shared => auth::endpoint_shared::encode::TYPE_ENDPOINT_SHARED, auth::endpoint_shared::project::EndpointSharedProjector, auth::endpoint_shared::project::PROJECTOR_INFO, auth::endpoint_shared::project::STORAGE_REQUIREMENT;
    project_invite_server => auth::invite_server::encode::TYPE_INVITE_SERVER, auth::invite_server::project::InviteServerProjector, auth::invite_server::project::PROJECTOR_INFO, auth::invite_server::project::STORAGE_REQUIREMENT;
    project_admin => auth::admin::encode::TYPE_ADMIN, auth::admin::project::AdminProjector, auth::admin::project::PROJECTOR_INFO, auth::admin::project::STORAGE_REQUIREMENT;
    project_invite_accepted => auth::invite_accepted::encode::TYPE_INVITE_ACCEPTED, auth::invite_accepted::project::InviteAcceptedProjector, auth::invite_accepted::project::PROJECTOR_INFO, auth::invite_accepted::project::STORAGE_REQUIREMENT;
    project_retention_policy => content::retention_policy::encode::TYPE_RETENTION_POLICY, content::retention_policy::project::RetentionPolicyProjector, content::retention_policy::project::PROJECTOR_INFO, content::retention_policy::project::STORAGE_REQUIREMENT;
    project_sync_range_request => sync::range_request::encode::TYPE_SYNC_RANGE_REQUEST, sync::range_request::project::SyncRangeRequestProjector, sync::range_request::project::PROJECTOR_INFO, sync::range_request::project::STORAGE_REQUIREMENT;
    project_sync_shared_fact => sync::shared_fact::encode::TYPE_SHARED_FACT, sync::shared_fact::project::SyncSharedFactProjector, sync::shared_fact::project::PROJECTOR_INFO, sync::shared_fact::project::STORAGE_REQUIREMENT;
    project_sync_compare => sync::compare::encode::TYPE_SYNC_COMPARE, sync::compare::project::SyncCompareProjector, sync::compare::project::PROJECTOR_INFO, sync::compare::project::STORAGE_REQUIREMENT;
    project_sync_have_id => sync::have_id::encode::TYPE_SYNC_HAVE_ID, sync::have_id::project::SyncHaveIdProjector, sync::have_id::project::PROJECTOR_INFO, sync::have_id::project::STORAGE_REQUIREMENT;
    project_sync_need_id => sync::need_id::encode::TYPE_SYNC_NEED_ID, sync::need_id::project::SyncNeedIdProjector, sync::need_id::project::PROJECTOR_INFO, sync::need_id::project::STORAGE_REQUIREMENT;
    project_sync_local_setting => sync::local_setting::TYPE_SYNC_LOCAL_SETTING, sync::local_setting::SyncLocalSettingProjector, sync::local_setting::PROJECTOR_INFO, sync::local_setting::STORAGE_REQUIREMENT;
    project_versioning_local_update => versioning::local_update::encode::TYPE_VERSIONING_UPDATE, versioning::local_update::project::UpdateProjector, versioning::local_update::project::PROJECTOR_INFO, versioning::local_update::project::STORAGE_REQUIREMENT;
    project_connection_frame_small => connection::frame_small::encode::TYPE_CONNECTION_FRAME_SMALL, connection::frame_small::project::ConnectionFrameSmallProjector, connection::frame_small::project::PROJECTOR_INFO, connection::frame_small::project::STORAGE_REQUIREMENT;
    project_connection_frame_file_slice => connection::frame_file_slice::encode::TYPE_CONNECTION_FRAME_FILE_SLICE, connection::frame_file_slice::project::ConnectionFrameFileSliceProjector, connection::frame_file_slice::project::PROJECTOR_INFO, connection::frame_file_slice::project::STORAGE_REQUIREMENT;
    project_connection_frame_bundle => connection::frame_bundle::encode::TYPE_CONNECTION_FRAME_BUNDLE, connection::frame_bundle::project::ConnectionFrameBundleProjector, connection::frame_bundle::project::PROJECTOR_INFO, connection::frame_bundle::project::STORAGE_REQUIREMENT;
    project_connection_frame_observation => connection::frame_observation::encode::TYPE_CONNECTION_FRAME_OBSERVATION, connection::frame_observation::project::ConnectionFrameObservationProjector, connection::frame_observation::project::PROJECTOR_INFO, connection::frame_observation::project::STORAGE_REQUIREMENT;
    project_connection_fact_receipt => connection::fact_receipt::encode::TYPE_CONNECTION_FACT_RECEIPT, connection::fact_receipt::project::ConnectionFactReceiptProjector, connection::fact_receipt::project::PROJECTOR_INFO, connection::fact_receipt::project::STORAGE_REQUIREMENT;
    project_user_invite => auth::user_invite::encode::TYPE_USER_INVITE, auth::user_invite::project::UserInviteProjector, auth::user_invite::project::PROJECTOR_INFO, auth::user_invite::project::STORAGE_REQUIREMENT;
    project_user => auth::user::encode::TYPE_USER, auth::user::project::UserProjector, auth::user::project::PROJECTOR_INFO, auth::user::project::STORAGE_REQUIREMENT;
}

// Every route names one intent kind and its handler. Replay behavior belongs at
// the handler edge through `HandlerContext::is_replay()`. `recurring =
// <RecurringIntentSpec>` marks a live operational loop that each runtime turn
// offers as in-memory local work; the builder decides whether current state
// actually needs a queued intent.
macro_rules! handler_route {
    ($intent_kind:path, $handler:path, storage = $storage_requirement:path) => {
        HandlerRoute {
            intent_kind: $intent_kind,
            factory: || Box::new(<$handler>::new()),
            storage_requirement: $storage_requirement,
            recurrence: None,
        }
    };
    ($intent_kind:path, $handler:path, storage = $storage_requirement:path, recurring = $spec:expr) => {
        HandlerRoute {
            intent_kind: $intent_kind,
            factory: || Box::new(<$handler>::new()),
            storage_requirement: $storage_requirement,
            recurrence: Some($spec),
        }
    };
}

pub(crate) const HANDLER_ROUTES: &[HandlerRoute] = &[
    // Version checks are protocol policy. The recurring intent compares the
    // binary's protocol version with projected local version state and emits a
    // local update fact when a rebuild is needed.
    handler_route!(
        versioning::check_version::CHECK_VERSION,
        versioning::check_version::CheckVersionHandler,
        storage = versioning::check_version::STORAGE_REQUIREMENT,
        recurring = RecurringIntentSpec {
            build_intent: versioning::check_version::build_check_version_intent,
        }
    ),
    // Handshake/sync sends and the response builders are operational IO over a
    // live session, rebuilt from committed request/response facts after the
    // barrier — never replay-time work.
    handler_route!(
        connection::create_connection::CREATE_CONNECTION,
        connection::create_connection::CreateConnectionHandler,
        storage = connection::create_connection::STORAGE_REQUIREMENT
    ),
    handler_route!(
        sync::send_compare_response::SEND_SYNC_COMPARE_RESPONSE,
        sync::send_compare_response::SendSyncCompareResponseHandler,
        storage = sync::send_compare_response::STORAGE_REQUIREMENT
    ),
    handler_route!(
        sync::send_needed_fact_id::SEND_NEEDED_FACT_ID,
        sync::send_needed_fact_id::SendNeededFactIdHandler,
        storage = sync::send_needed_fact_id::STORAGE_REQUIREMENT
    ),
    handler_route!(
        sync::send_requested_fact::SEND_REQUESTED_FACT,
        sync::send_requested_fact::SendRequestedFactHandler,
        storage = sync::send_requested_fact::STORAGE_REQUIREMENT
    ),
    // share_fact_with_sync rebuilds sync-derived shareable/negentropy state from
    // retained facts: deterministic replay rebuild work.
    handler_route!(
        sync::share_fact_with_sync::SHARE_FACT_WITH_SYNC,
        sync::share_fact_with_sync::ShareFactWithSyncHandler,
        storage = sync::share_fact_with_sync::STORAGE_REQUIREMENT
    ),
    // Seeding sync runs only for connections explicitly recreated after replay.
    handler_route!(
        sync::seed_connection::SEED_CONNECTION_SYNC,
        sync::seed_connection::SeedConnectionSyncHandler,
        storage = sync::seed_connection::STORAGE_REQUIREMENT
    ),
    // Sync maintenance is a live recurring operational loop. User-facing sync
    // settings affect it through projected local state.
    handler_route!(
        sync::maintain_sync::MAINTAIN_SYNC,
        sync::maintain_sync::MaintainSyncHandler,
        storage = sync::maintain_sync::STORAGE_REQUIREMENT,
        recurring = RecurringIntentSpec {
            build_intent: sync::maintain_sync::build_maintain_sync_intent,
        }
    ),
    // Connection maintenance is a live recurring operational loop. Runtime
    // turns offer it in-memory; it re-sends unanswered local outbound requests
    // and never runs during replay. This replaces the wall-clock
    // connection_peer_retry wake.
    handler_route!(
        connection::maintain_connections::MAINTAIN_CONNECTIONS,
        connection::maintain_connections::MaintainConnectionsHandler,
        storage = connection::maintain_connections::STORAGE_REQUIREMENT,
        recurring = RecurringIntentSpec {
            build_intent: connection::maintain_connections::build_maintain_connections_intent,
        }
    ),
    // Sending facts over a connection and route-resolved outgoing frame
    // queueing are operational IO over a live session.
    handler_route!(
        connection::send_facts_on_connection::SEND_FACTS_ON_CONNECTION,
        connection::send_facts_on_connection::SendFactsOnConnectionHandler,
        storage = connection::send_facts_on_connection::STORAGE_REQUIREMENT
    ),
    handler_route!(
        connection::queue_outgoing_frame::QUEUE_OUTGOING_FRAME,
        connection::queue_outgoing_frame::QueueOutgoingFrameHandler,
        storage = connection::queue_outgoing_frame::STORAGE_REQUIREMENT
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
