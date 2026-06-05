//! Verus model for the first connection-to-sync confidentiality bracket.
//!
//! This file is verified directly by `scripts/run_verus.sh`; it is not part of
//! normal Rust builds. The model deliberately proves a small vertical slice:
//! once a connection row exists, workspace-message bytes can be selected by the
//! sync visibility path only when the remote endpoint is already a workspace
//! member or this connection carries a scoped bootstrap invite for that
//! workspace.
//!
//! This proof does not claim that the final `send_facts_on_connection` handler
//! independently enforces visibility for arbitrary explicit intents. It proves
//! the sync-selected bracket: seed/range/live-tail/need-id producers must select
//! workspace facts through connection visibility before packaging them.

use vstd::prelude::*;

verus! {

pub type Id = int;

pub struct ConnectionRow {
    pub connection_id: Id,
    pub from_endpoint: Id,
    pub to_endpoint: Id,
}

pub struct WorkspaceMessage {
    pub workspace_id: Id,
}

pub open spec fn remote_endpoint(row: ConnectionRow, local_endpoint: Id) -> Option<Id> {
    if row.from_endpoint == local_endpoint {
        Some(row.to_endpoint)
    } else if row.to_endpoint == local_endpoint {
        Some(row.from_endpoint)
    } else {
        None
    }
}

pub open spec fn endpoint_is_member(
    endpoint_memberships: Set<(Id, Id)>,
    workspace_id: Id,
    endpoint_id: Id,
) -> bool {
    endpoint_memberships.contains((workspace_id, endpoint_id))
}

pub open spec fn scoped_bootstrap_invite_authorizes_connection(
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
    connection_id: Id,
    endpoint_id: Id,
    workspace_id: Id,
) -> bool {
    scoped_bootstrap_invites.contains((connection_id, endpoint_id, workspace_id))
}

pub open spec fn connection_authorizes_workspace(
    row: ConnectionRow,
    local_endpoint: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
) -> bool {
    match remote_endpoint(row, local_endpoint) {
        Some(remote) => {
            endpoint_is_member(endpoint_memberships, workspace_id, remote)
                || scoped_bootstrap_invite_authorizes_connection(
                    scoped_bootstrap_invites,
                    row.connection_id,
                    remote,
                    workspace_id,
                )
        },
        None => false,
    }
}

pub open spec fn sync_visibility_selects_workspace_message(
    row: ConnectionRow,
    local_endpoint: Id,
    message: WorkspaceMessage,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
) -> bool {
    connection_authorizes_workspace(
        row,
        local_endpoint,
        message.workspace_id,
        endpoint_memberships,
        scoped_bootstrap_invites,
    )
}

pub open spec fn never_invited_on_connection_for_workspace(
    row: ConnectionRow,
    local_endpoint: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
) -> bool {
    match remote_endpoint(row, local_endpoint) {
        Some(remote) => {
            !endpoint_is_member(endpoint_memberships, workspace_id, remote)
                && !scoped_bootstrap_invite_authorizes_connection(
                    scoped_bootstrap_invites,
                    row.connection_id,
                    remote,
                    workspace_id,
                )
        },
        None => true,
    }
}

pub proof fn never_invited_remote_cannot_receive_workspace_message_from_sync(
    row: ConnectionRow,
    local_endpoint: Id,
    message: WorkspaceMessage,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        never_invited_on_connection_for_workspace(
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
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
}

pub proof fn endpoint_membership_is_sufficient_for_sync_visibility(
    row: ConnectionRow,
    local_endpoint: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        row.from_endpoint == local_endpoint,
        endpoint_memberships.contains((workspace_id, row.to_endpoint)),
    ensures
        connection_authorizes_workspace(
            row,
            local_endpoint,
            workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
}

pub proof fn scoped_bootstrap_invite_is_intentional_memberless_visibility(
    row: ConnectionRow,
    local_endpoint: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        row.from_endpoint == local_endpoint,
        !endpoint_memberships.contains((workspace_id, row.to_endpoint)),
        scoped_bootstrap_invites.contains((row.connection_id, row.to_endpoint, workspace_id)),
    ensures
        connection_authorizes_workspace(
            row,
            local_endpoint,
            workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
        !never_invited_on_connection_for_workspace(
            row,
            local_endpoint,
            workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
}

pub proof fn connection_not_involving_local_endpoint_authorizes_no_workspace(
    row: ConnectionRow,
    local_endpoint: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        row.from_endpoint != local_endpoint,
        row.to_endpoint != local_endpoint,
    ensures
        !connection_authorizes_workspace(
            row,
            local_endpoint,
            workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
}

} // verus!
