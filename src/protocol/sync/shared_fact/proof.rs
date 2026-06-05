//! Verus model for sync workspace-message visibility.
//!
//! This proof is local to the sync visibility boundary. A workspace message is
//! selected for a connection only when the message is shareable and the
//! connection authorizes the message workspace.

use crate::connection_connection_proof;
use crate::Id;
use vstd::prelude::*;

verus! {

pub struct WorkspaceMessage {
    pub message_id: Id,
    pub workspace_id: Id,
}

pub open spec fn workspace_message_is_shareable(
    shareable_workspace_messages: Set<(Id, Id)>,
    message: WorkspaceMessage,
) -> bool {
    shareable_workspace_messages.contains((message.workspace_id, message.message_id))
}

pub open spec fn sync_visibility_selects_workspace_message(
    row: connection_connection_proof::ConnectionRow,
    local_endpoint: Id,
    message: WorkspaceMessage,
    shareable_workspace_messages: Set<(Id, Id)>,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
) -> bool {
    workspace_message_is_shareable(shareable_workspace_messages, message)
        && connection_connection_proof::connection_authorizes_workspace(
            row,
            local_endpoint,
            message.workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        )
}

pub proof fn selected_workspace_message_requires_connection_authorization(
    row: connection_connection_proof::ConnectionRow,
    local_endpoint: Id,
    message: WorkspaceMessage,
    shareable_workspace_messages: Set<(Id, Id)>,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        sync_visibility_selects_workspace_message(
            row,
            local_endpoint,
            message,
            shareable_workspace_messages,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
    ensures
        connection_connection_proof::connection_authorizes_workspace(
            row,
            local_endpoint,
            message.workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
}

pub proof fn not_authorized_connection_cannot_select_workspace_message(
    row: connection_connection_proof::ConnectionRow,
    local_endpoint: Id,
    message: WorkspaceMessage,
    shareable_workspace_messages: Set<(Id, Id)>,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        !connection_connection_proof::connection_authorizes_workspace(
            row,
            local_endpoint,
            message.workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
    ensures
        !sync_visibility_selects_workspace_message(
            row,
            local_endpoint,
            message,
            shareable_workspace_messages,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
}

pub proof fn shareable_and_authorized_connection_selects_workspace_message(
    row: connection_connection_proof::ConnectionRow,
    local_endpoint: Id,
    message: WorkspaceMessage,
    shareable_workspace_messages: Set<(Id, Id)>,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        workspace_message_is_shareable(shareable_workspace_messages, message),
        connection_connection_proof::connection_authorizes_workspace(
            row,
            local_endpoint,
            message.workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
    ensures
        sync_visibility_selects_workspace_message(
            row,
            local_endpoint,
            message,
            shareable_workspace_messages,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
}

} // verus!
