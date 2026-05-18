//! Declarative registry for the target protocol.
//!
//! This file names the facts, context matchers, intents, handlers, and schema
//! sources that make up the poc-10 protocol. It is intentionally a table of
//! contents, not a runtime. Module manifests (`event_modules.rs` and
//! `handlers.rs`) keep Rust namespaces visible; this registry says which of
//! those namespaces are part of the concrete protocol.

pub mod runtime;

use crate::core::schema_dsl::{
    CORE_SCHEMA_SOURCE, EVENT_MODULES_SCHEMA_SOURCE, HANDLERS_SCHEMA_SOURCE,
};
use crate::event_modules::{
    connection_ephemeral_secret, connection_request, connection_response, content_event,
    content_file, content_file_deletion, content_file_slice, content_message,
    content_message_deletion, content_reaction, disappearing_messages_setting, encryption,
    identity_admin, identity_device_invite, identity_endpoint, identity_endpoint_shared,
    identity_invite, identity_invite_accepted, identity_invite_server, identity_user,
    identity_user_invite, identity_workspace, local_history_node_secret, removal_frontier,
    sealed_message, signed_fact, sync_compare, sync_encrypted_root, sync_have_id,
    sync_key_wrap_available, sync_need_id, sync_range_request, sync_shared_event, transit_received,
};
use crate::handlers::{
    bootstrap_send, connection, connection_response as connection_response_handler, handle_sync,
    network_send, purge_cascade, receive_transit, retention_expiry, retention_floor,
    sync_index_update, transit,
};

/// Concrete protocol selected by the `match` binary.
pub struct Protocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolRegistry {
    pub name: &'static str,
    pub schemas: &'static [SchemaRegistration],
    pub facts: &'static [FactRegistration],
    pub context_matchers: &'static [ContextMatcherRegistration],
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
pub struct ContextMatcherRegistration {
    pub role: &'static str,
    pub matcher: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentRegistration {
    pub kind: &'static str,
    pub execution: IntentExecutionKind,
    pub declared_by: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentExecutionKind {
    Atomic,
    Deferred,
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
    facts: FACTS,
    context_matchers: CONTEXT_MATCHERS,
    intents: INTENTS,
    handlers: HANDLERS,
};

pub const SCHEMAS: &[SchemaRegistration] = &[
    SchemaRegistration {
        name: "core",
        source: CORE_SCHEMA_SOURCE,
    },
    SchemaRegistration {
        name: "event_modules",
        source: EVENT_MODULES_SCHEMA_SOURCE,
    },
    SchemaRegistration {
        name: "handlers",
        source: HANDLERS_SCHEMA_SOURCE,
    },
];

pub const FACTS: &[FactRegistration] = &[
    FactRegistration {
        module: "connection_ephemeral_secret",
        name: "connection_ephemeral_secret",
        tag: connection_ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET,
        projector: "ConnectionEphemeralSecretProjector",
    },
    FactRegistration {
        module: "connection_request",
        name: "connection_request",
        tag: connection_request::layout::TYPE_CONNECTION_REQUEST,
        projector: "ConnectionRequestProjector",
    },
    FactRegistration {
        module: "connection_response",
        name: "connection_response",
        tag: connection_response::layout::TYPE_CONNECTION_RESPONSE,
        projector: "ConnectionResponseProjector",
    },
    FactRegistration {
        module: "content_event",
        name: "content_event",
        tag: content_event::layout::TYPE_CONTENT_EVENT,
        projector: "ContentEventProjector",
    },
    FactRegistration {
        module: "content_file",
        name: "content_file",
        tag: content_file::layout::TYPE_CONTENT_FILE,
        projector: "ContentFileProjector",
    },
    FactRegistration {
        module: "content_file_deletion",
        name: "content_file_deletion",
        tag: content_file_deletion::layout::TYPE_CONTENT_FILE_DELETION,
        projector: "ContentFileDeletionProjector",
    },
    FactRegistration {
        module: "content_file_slice",
        name: "content_file_slice",
        tag: content_file_slice::layout::TYPE_CONTENT_FILE_SLICE,
        projector: "ContentFileSliceProjector",
    },
    FactRegistration {
        module: "content_message",
        name: "content_message",
        tag: content_message::layout::TYPE_CONTENT_MESSAGE,
        projector: "ContentMessageProjector",
    },
    FactRegistration {
        module: "content_message_deletion",
        name: "content_message_deletion",
        tag: content_message_deletion::layout::TYPE_CONTENT_MESSAGE_DELETION,
        projector: "ContentMessageDeletionProjector",
    },
    FactRegistration {
        module: "content_reaction",
        name: "content_reaction",
        tag: content_reaction::layout::TYPE_CONTENT_REACTION,
        projector: "ContentReactionProjector",
    },
    FactRegistration {
        module: "disappearing_messages_setting",
        name: "disappearing_messages_setting",
        tag: disappearing_messages_setting::layout::TYPE_DISAPPEARING_MESSAGES_SETTING,
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
        module: "identity_admin",
        name: "admin",
        tag: identity_admin::layout::TYPE_ADMIN,
        projector: "AdminProjector",
    },
    FactRegistration {
        module: "identity_device_invite",
        name: "device_invite",
        tag: identity_device_invite::layout::TYPE_DEVICE_INVITE,
        projector: "DeviceInviteProjector",
    },
    FactRegistration {
        module: "identity_endpoint",
        name: "local_endpoint",
        tag: identity_endpoint::layout::TYPE_LOCAL_ENDPOINT,
        projector: "EndpointProjector",
    },
    FactRegistration {
        module: "identity_endpoint_shared",
        name: "endpoint_shared",
        tag: identity_endpoint_shared::layout::TYPE_ENDPOINT_SHARED,
        projector: "EndpointSharedProjector",
    },
    FactRegistration {
        module: "identity_invite",
        name: "invite_secret",
        tag: identity_invite::layout::TYPE_INVITE_SECRET,
        projector: "InviteSecretProjector",
    },
    FactRegistration {
        module: "identity_invite_accepted",
        name: "invite_accepted",
        tag: identity_invite_accepted::layout::TYPE_INVITE_ACCEPTED,
        projector: "InviteAcceptedProjector",
    },
    FactRegistration {
        module: "identity_invite_server",
        name: "invite_server",
        tag: identity_invite_server::layout::TYPE_INVITE_SERVER,
        projector: "InviteServerProjector",
    },
    FactRegistration {
        module: "identity_user",
        name: "user",
        tag: identity_user::layout::TYPE_USER,
        projector: "UserProjector",
    },
    FactRegistration {
        module: "identity_user_invite",
        name: "user_invite",
        tag: identity_user_invite::layout::TYPE_USER_INVITE,
        projector: "UserInviteProjector",
    },
    FactRegistration {
        module: "identity_workspace",
        name: "workspace",
        tag: identity_workspace::layout::TYPE_WORKSPACE,
        projector: "WorkspaceProjector",
    },
    FactRegistration {
        module: "local_history_node_secret",
        name: "local_history_node_secret",
        tag: local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET,
        projector: "LocalHistoryNodeSecretProjector",
    },
    FactRegistration {
        module: "removal_frontier",
        name: "removal_frontier",
        tag: removal_frontier::layout::TYPE_REMOVAL_FRONTIER,
        projector: "RemovalFrontierProjector",
    },
    FactRegistration {
        module: "sealed_message",
        name: "sealed_message",
        tag: sealed_message::layout::TYPE_SEALED_MESSAGE,
        projector: "SealedMessageProjector",
    },
    FactRegistration {
        module: "sealed_message",
        name: "signer_pubkey",
        tag: sealed_message::layout::TYPE_SIGNER_PUBKEY,
        projector: "SealedMessageProjector",
    },
    FactRegistration {
        module: "sealed_message",
        name: "secret_node",
        tag: sealed_message::layout::TYPE_SECRET_NODE,
        projector: "SealedMessageProjector",
    },
    FactRegistration {
        module: "sealed_message",
        name: "message_deletion",
        tag: sealed_message::layout::TYPE_MESSAGE_DELETION,
        projector: "SealedMessageProjector",
    },
    FactRegistration {
        module: "signed_fact",
        name: "signed_fact",
        tag: signed_fact::layout::TYPE_SIGNED_FACT,
        projector: "SignedFactProjector",
    },
    FactRegistration {
        module: "signed_fact",
        name: "local_signer_secret",
        tag: signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET,
        projector: "SignedFactProjector",
    },
    FactRegistration {
        module: "sync_range_request",
        name: "sync_range_request",
        tag: sync_range_request::layout::TYPE_SYNC_RANGE_REQUEST,
        projector: "SyncRangeRequestProjector",
    },
    FactRegistration {
        module: "sync_encrypted_root",
        name: "encrypted_root",
        tag: sync_encrypted_root::layout::TYPE_ENCRYPTED_ROOT,
        projector: "SyncEncryptedRootProjector",
    },
    FactRegistration {
        module: "sync_shared_event",
        name: "shared_event",
        tag: sync_shared_event::layout::TYPE_SHARED_EVENT,
        projector: "SyncSharedEventProjector",
    },
    FactRegistration {
        module: "sync_key_wrap_available",
        name: "key_wrap_available",
        tag: sync_key_wrap_available::layout::TYPE_KEY_WRAP_AVAILABLE,
        projector: "SyncKeyWrapAvailableProjector",
    },
    FactRegistration {
        module: "sync_compare",
        name: "sync_compare",
        tag: sync_compare::layout::TYPE_SYNC_COMPARE,
        projector: "SyncCompareProjector",
    },
    FactRegistration {
        module: "sync_have_id",
        name: "sync_have_id",
        tag: sync_have_id::layout::TYPE_SYNC_HAVE_ID,
        projector: "SyncHaveIdProjector",
    },
    FactRegistration {
        module: "sync_need_id",
        name: "sync_need_id",
        tag: sync_need_id::layout::TYPE_SYNC_NEED_ID,
        projector: "SyncNeedIdProjector",
    },
    FactRegistration {
        module: "transit_received",
        name: "transit_received",
        tag: transit_received::layout::TYPE_TRANSIT_RECEIVED,
        projector: "TransitReceivedProjector",
    },
];

pub const CONTEXT_MATCHERS: &[ContextMatcherRegistration] = &[
    ContextMatcherRegistration {
        role: "connection_ephemeral_secret",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "connection_invite_secret",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "connection_request",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "content_file",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "content_message",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "disappearing_authority",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "disappearing_previous",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "content_deleted",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "identity_admin",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "identity_device_invite",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "identity_device_invite_key",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "identity_endpoint_shared",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "identity_invite_secret",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "identity_invite_server",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "identity_invite_server_key",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "identity_user",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "identity_user_invite",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "identity_user_invite_key",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "identity_workspace",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "local_recipient_key",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "local_secret_source",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "local_signer_secret",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "recipient_key",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "recipient_superseded",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "removal_frontier",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "removal_ref",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "secret_coverage",
        matcher: "SecretCoverageMatcher",
    },
    ContextMatcherRegistration {
        role: "signer_pubkey",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "sync_exact_event",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "sync_key_wrap",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "sync_range_event",
        matcher: "RangeEventMatcher",
    },
    ContextMatcherRegistration {
        role: "transit_received",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "wrap_source",
        matcher: "WrapSourceMatcher",
    },
];

pub const INTENTS: &[IntentRegistration] = &[
    IntentRegistration {
        kind: "put_row",
        execution: IntentExecutionKind::Atomic,
        declared_by: "core",
    },
    IntentRegistration {
        kind: "delete_row",
        execution: IntentExecutionKind::Atomic,
        declared_by: "core",
    },
    IntentRegistration {
        kind: bootstrap_send::BOOTSTRAP_SEND_REQUEST,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::bootstrap_send",
    },
    IntentRegistration {
        kind: connection::CONNECTION_MARK_SENT,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::connection",
    },
    IntentRegistration {
        kind: connection::CONNECTION_SEND_FRAME,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::connection",
    },
    IntentRegistration {
        kind: connection::CONNECTION_SEND_REQUEST,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::connection",
    },
    IntentRegistration {
        kind: connection::CONNECTION_SEND_RESPONSE,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::connection",
    },
    IntentRegistration {
        kind: connection_response_handler::CONNECTION_RESPONSE,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::connection_response",
    },
    IntentRegistration {
        kind: encryption::intent::MATERIALIZE_KEY_WRAPS,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::materialize_key_wraps",
    },
    IntentRegistration {
        kind: encryption::intent::PURGE_RETIRED_RECIPIENT_MATERIAL,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::purge_retired_recipient_material",
    },
    IntentRegistration {
        kind: encryption::intent::UNWRAP_KEY_WRAP,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::unwrap_key_wrap",
    },
    IntentRegistration {
        kind: handle_sync::PROCESS_SYNC_INBOUND,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::handle_sync",
    },
    IntentRegistration {
        kind: handle_sync::SYNC_NEED_ID,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::handle_sync",
    },
    IntentRegistration {
        kind: handle_sync::RESPOND_TO_SYNC_COMPARE,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::handle_sync",
    },
    IntentRegistration {
        kind: handle_sync::REQUEST_SYNC_ID,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::handle_sync",
    },
    IntentRegistration {
        kind: handle_sync::RESPOND_TO_SYNC_NEED,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::handle_sync",
    },
    IntentRegistration {
        kind: handle_sync::SEED_SYNC_CONNECTION,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::handle_sync",
    },
    IntentRegistration {
        kind: network_send::NETWORK_SEND_FRAME,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::network_send",
    },
    IntentRegistration {
        kind: receive_transit::RECEIVE_TRANSIT_FRAME,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::receive_transit",
    },
    IntentRegistration {
        kind: sealed_message::intent::PURGE_EVENT,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::purge_event",
    },
    IntentRegistration {
        kind: purge_cascade::CASCADE_CHILD_PURGE,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::purge_cascade",
    },
    IntentRegistration {
        kind: retention_expiry::EXPIRE_MESSAGE,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::retention_expiry",
    },
    IntentRegistration {
        kind: retention_floor::APPLY_RETENTION_FLOOR,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::retention_floor",
    },
    IntentRegistration {
        kind: sync_index_update::RECORD_INDEXED_EVENT,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::sync_index_update",
    },
    IntentRegistration {
        kind: transit::TRANSIT_SEND_ON_CONNECTION,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::transit",
    },
    IntentRegistration {
        kind: transit::TRANSIT_WRAP_CONNECTION_BATCH,
        execution: IntentExecutionKind::Deferred,
        declared_by: "handlers::transit",
    },
];

pub const HANDLERS: &[HandlerRegistration] = &[
    HandlerRegistration {
        module: "bootstrap_send",
        handler: "BootstrapSendRequestHandler",
        runtime_field: "bootstrap_send",
        intents: &[bootstrap_send::BOOTSTRAP_SEND_REQUEST],
    },
    HandlerRegistration {
        module: "connection_response",
        handler: "ConnectionResponseHandler",
        runtime_field: "connection_response",
        intents: &[connection_response_handler::CONNECTION_RESPONSE],
    },
    HandlerRegistration {
        module: "handle_sync",
        handler: "HandleSyncHandler",
        runtime_field: "handle_sync",
        intents: &[handle_sync::PROCESS_SYNC_INBOUND, handle_sync::SYNC_NEED_ID],
    },
    HandlerRegistration {
        module: "handle_sync",
        handler: "RespondToSyncCompareHandler",
        runtime_field: "respond_to_sync_compare",
        intents: &[handle_sync::RESPOND_TO_SYNC_COMPARE],
    },
    HandlerRegistration {
        module: "handle_sync",
        handler: "RequestSyncIdHandler",
        runtime_field: "request_sync_id",
        intents: &[handle_sync::REQUEST_SYNC_ID],
    },
    HandlerRegistration {
        module: "handle_sync",
        handler: "RespondToSyncNeedHandler",
        runtime_field: "respond_to_sync_need",
        intents: &[handle_sync::RESPOND_TO_SYNC_NEED],
    },
    HandlerRegistration {
        module: "handle_sync",
        handler: "SeedSyncConnectionHandler",
        runtime_field: "seed_sync_connection",
        intents: &[handle_sync::SEED_SYNC_CONNECTION],
    },
    HandlerRegistration {
        module: "materialize_key_wraps",
        handler: "MaterializeKeyWrapsHandler",
        runtime_field: "materialize_key_wraps",
        intents: &[encryption::intent::MATERIALIZE_KEY_WRAPS],
    },
    HandlerRegistration {
        module: "network_send",
        handler: "NetworkSendHandler",
        runtime_field: "network_send",
        intents: &[network_send::NETWORK_SEND_FRAME],
    },
    HandlerRegistration {
        module: "purge_event",
        handler: "PurgeEventHandler",
        runtime_field: "purge_event",
        intents: &[sealed_message::intent::PURGE_EVENT],
    },
    HandlerRegistration {
        module: "purge_cascade",
        handler: "PurgeCascadeHandler",
        runtime_field: "purge_cascade",
        intents: &[purge_cascade::CASCADE_CHILD_PURGE],
    },
    HandlerRegistration {
        module: "purge_retired_recipient_material",
        handler: "PurgeRetiredRecipientMaterialHandler",
        runtime_field: "purge_retired_recipient_material",
        intents: &[encryption::intent::PURGE_RETIRED_RECIPIENT_MATERIAL],
    },
    HandlerRegistration {
        module: "receive_transit",
        handler: "ReceiveTransitHandler",
        runtime_field: "receive_transit",
        intents: &[receive_transit::RECEIVE_TRANSIT_FRAME],
    },
    HandlerRegistration {
        module: "retention_expiry",
        handler: "RetentionExpiryHandler",
        runtime_field: "retention_expiry",
        intents: &[retention_expiry::EXPIRE_MESSAGE],
    },
    HandlerRegistration {
        module: "retention_floor",
        handler: "RetentionFloorHandler",
        runtime_field: "retention_floor",
        intents: &[retention_floor::APPLY_RETENTION_FLOOR],
    },
    HandlerRegistration {
        module: "sync_index_update",
        handler: "SyncIndexUpdateHandler",
        runtime_field: "sync_index_update",
        intents: &[sync_index_update::RECORD_INDEXED_EVENT],
    },
    HandlerRegistration {
        module: "transit",
        handler: "TransitSendOnConnectionHandler",
        runtime_field: "transit",
        intents: &[
            transit::TRANSIT_SEND_ON_CONNECTION,
            transit::TRANSIT_WRAP_CONNECTION_BATCH,
        ],
    },
    HandlerRegistration {
        module: "unwrap_key_wrap",
        handler: "UnwrapKeyWrapHandler",
        runtime_field: "unwrap_key_wrap",
        intents: &[encryption::intent::UNWRAP_KEY_WRAP],
    },
];
