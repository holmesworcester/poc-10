//! Verus model for connection-row workspace authorization.
//!
//! This proof is local to the connection projector boundary. A live connection
//! row can authorize a workspace only by identifying the remote endpoint and
//! carrying a valid request-authority certificate for that endpoint/workspace.

use crate::connection_request_proof;
use crate::Id;
use vstd::prelude::*;

verus! {

pub struct ConnectionRow {
    pub connection_id: Id,
    pub from_endpoint: Id,
    pub to_endpoint: Id,
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

pub open spec fn connection_authorizes_workspace(
    row: ConnectionRow,
    local_endpoint: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
) -> bool {
    match remote_endpoint(row, local_endpoint) {
        Some(remote) => {
            connection_request_proof::valid_connection_request_authority_for_workspace(
                row.connection_id,
                remote,
                workspace_id,
                endpoint_memberships,
                scoped_bootstrap_invites,
            )
        },
        None => false,
    }
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
            connection_request_proof::never_invited_for_workspace(
                row.connection_id,
                remote,
                workspace_id,
                endpoint_memberships,
                scoped_bootstrap_invites,
            )
        },
        None => true,
    }
}

pub proof fn endpoint_membership_authorizes_connection_workspace(
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
    connection_request_proof::endpoint_membership_grants_request_workspace_authority(
        row.connection_id,
        row.to_endpoint,
        workspace_id,
        endpoint_memberships,
        scoped_bootstrap_invites,
    );
}

pub proof fn scoped_bootstrap_invite_authorizes_connection_workspace(
    row: ConnectionRow,
    local_endpoint: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        row.from_endpoint == local_endpoint,
        scoped_bootstrap_invites.contains((row.connection_id, row.to_endpoint, workspace_id)),
    ensures
        connection_authorizes_workspace(
            row,
            local_endpoint,
            workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
    connection_request_proof::scoped_bootstrap_invite_grants_request_workspace_authority(
        row.connection_id,
        row.to_endpoint,
        workspace_id,
        endpoint_memberships,
        scoped_bootstrap_invites,
    );
}

pub proof fn never_invited_connection_authorizes_no_workspace(
    row: ConnectionRow,
    local_endpoint: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        never_invited_on_connection_for_workspace(
            row,
            local_endpoint,
            workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
    ensures
        !connection_authorizes_workspace(
            row,
            local_endpoint,
            workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
    match remote_endpoint(row, local_endpoint) {
        Some(remote) => {
            connection_request_proof::never_invited_has_no_connection_request_authority(
                row.connection_id,
                remote,
                workspace_id,
                endpoint_memberships,
                scoped_bootstrap_invites,
            );
        },
        None => {},
    }
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
