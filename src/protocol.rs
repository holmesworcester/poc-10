//! Declarative registry for the target protocol.
//!
//! This file names the facts, context matchers, intents, handlers, and schema
//! sources that make up the poc-10 protocol. It is intentionally a table of
//! contents, not a runtime. `facts.rs` and `intents.rs` keep
//! concrete protocol namespaces visible; this registry says which of those
//! namespaces are part of the concrete protocol.

pub mod facts;
pub(crate) mod intent_payload;
pub mod intents;
pub mod matchers;
pub mod runtime;

use crate::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE, INTENTS_SCHEMA_SOURCE};
use crate::protocol::facts::{connection, content, encryption, identity, sync, transport};
use crate::protocol::intents::{
    connection as connection_intents, content as content_intents, sync as sync_intents,
    transport as transport_intents,
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
    Ephemeral,
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
        role: "content_message_meta",
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
        role: "encryption_removal_frontier",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "secret_coverage",
        matcher: "SecretCoverageMatcher",
    },
    ContextMatcherRegistration {
        role: "content_signer",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "sync_exact_fact",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "sync_key_wrap",
        matcher: "ExactSelectorMatcher",
    },
    ContextMatcherRegistration {
        role: "sync_range_fact",
        matcher: "RangeFactMatcher",
    },
    ContextMatcherRegistration {
        role: "transport_transit_received",
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
        kind: connection_intents::send_bootstrap_request::SEND_BOOTSTRAP_CONNECTION_REQUEST,
        execution: IntentExecutionKind::Ephemeral,
        declared_by: "intents::connection::send_bootstrap_request",
    },
    IntentRegistration {
        kind: connection_intents::create_response::CREATE_CONNECTION_RESPONSE,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::connection::create_response",
    },
    IntentRegistration {
        kind: encryption::intent::CREATE_KEY_WRAP,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::encryption::create_key_wrap",
    },
    IntentRegistration {
        kind: encryption::intent::PURGE_RETIRED_RECIPIENT_MATERIAL,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::encryption::purge_retired_recipient_material",
    },
    IntentRegistration {
        kind: encryption::intent::UNWRAP_KEY_WRAP,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::encryption::unwrap_key_wrap",
    },
    IntentRegistration {
        kind: sync_intents::send_compare_response::SEND_SYNC_COMPARE_RESPONSE,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::sync::send_compare_response",
    },
    IntentRegistration {
        kind: sync_intents::send_needed_fact_id::SEND_NEEDED_FACT_ID,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::sync::send_needed_fact_id",
    },
    IntentRegistration {
        kind: sync_intents::send_requested_fact::SEND_REQUESTED_FACT,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::sync::send_requested_fact",
    },
    IntentRegistration {
        kind: sync_intents::share_fact_with_workspace::SHARE_FACT_WITH_WORKSPACE,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::sync::share_fact_with_workspace",
    },
    IntentRegistration {
        kind: sync_intents::seed_connection::SEED_CONNECTION_SYNC,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::sync::seed_connection",
    },
    IntentRegistration {
        kind: transport_intents::send_facts_on_connection::SEND_FACTS_ON_CONNECTION,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::transport::send_facts_on_connection",
    },
    IntentRegistration {
        kind: transport_intents::send_network_frame::SEND_NETWORK_FRAME,
        execution: IntentExecutionKind::Ephemeral,
        declared_by: "intents::transport::send_network_frame",
    },
    IntentRegistration {
        kind: transport_intents::receive_transit_frame::RECEIVE_TRANSIT_FRAME,
        execution: IntentExecutionKind::Ephemeral,
        declared_by: "intents::transport::receive_transit_frame",
    },
    IntentRegistration {
        kind: content_intents::purge_deleted_message::PURGE_DELETED_MESSAGE,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::content::purge_deleted_message",
    },
    IntentRegistration {
        kind: content_intents::purge_message_child::PURGE_MESSAGE_CHILD,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::content::purge_message_child",
    },
    IntentRegistration {
        kind: content_intents::purge_expired_message::PURGE_EXPIRED_MESSAGE,
        execution: IntentExecutionKind::Deferred,
        declared_by: "intents::content::purge_expired_message",
    },
    IntentRegistration {
        kind: content_intents::purge_below_retention_floor::PURGE_BELOW_RETENTION_FLOOR,
        execution: IntentExecutionKind::Deferred,
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
