//! Verus model for connection-request authority certificates.
//!
//! This proof is local to the request authority decision: a request can support
//! workspace visibility only through endpoint membership or a scoped bootstrap
//! invite. The concrete projector still has to connect these predicates to the
//! request bytes, signatures, invite secret, endpoint-shared context, and mutual
//! membership checks.

use crate::Id;
use vstd::prelude::*;

verus! {

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

pub open spec fn valid_connection_request_authority_for_workspace(
    connection_id: Id,
    remote_endpoint_id: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
) -> bool {
    endpoint_is_member(endpoint_memberships, workspace_id, remote_endpoint_id)
        || scoped_bootstrap_invite_authorizes_connection(
            scoped_bootstrap_invites,
            connection_id,
            remote_endpoint_id,
            workspace_id,
        )
}

pub open spec fn never_invited_for_workspace(
    connection_id: Id,
    remote_endpoint_id: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
) -> bool {
    !endpoint_is_member(endpoint_memberships, workspace_id, remote_endpoint_id)
        && !scoped_bootstrap_invite_authorizes_connection(
            scoped_bootstrap_invites,
            connection_id,
            remote_endpoint_id,
            workspace_id,
        )
}

pub proof fn endpoint_membership_grants_request_workspace_authority(
    connection_id: Id,
    remote_endpoint_id: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        endpoint_memberships.contains((workspace_id, remote_endpoint_id)),
    ensures
        valid_connection_request_authority_for_workspace(
            connection_id,
            remote_endpoint_id,
            workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
}

pub proof fn scoped_bootstrap_invite_grants_request_workspace_authority(
    connection_id: Id,
    remote_endpoint_id: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        scoped_bootstrap_invites.contains((connection_id, remote_endpoint_id, workspace_id)),
    ensures
        valid_connection_request_authority_for_workspace(
            connection_id,
            remote_endpoint_id,
            workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
}

pub proof fn never_invited_has_no_connection_request_authority(
    connection_id: Id,
    remote_endpoint_id: Id,
    workspace_id: Id,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        never_invited_for_workspace(
            connection_id,
            remote_endpoint_id,
            workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
    ensures
        !valid_connection_request_authority_for_workspace(
            connection_id,
            remote_endpoint_id,
            workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
}

} // verus!
