//! Root Verus composition proofs for protocol-level invariants.
//!
//! Local proof files own their executable boundaries. This root file composes
//! their certificates into threat-model invariants that span protocol scopes.

use vstd::prelude::*;

verus! {

pub type Id = int;

} // verus!

#[path = "connection/request/proof.rs"]
mod connection_request_proof;
#[path = "connection/connection/proof.rs"]
mod connection_connection_proof;
#[path = "sync/shared_fact/proof.rs"]
mod sync_shared_fact_proof;

verus! {

pub proof fn never_invited_remote_cannot_receive_workspace_message_from_sync(
    row: connection_connection_proof::ConnectionRow,
    local_endpoint: Id,
    message: sync_shared_fact_proof::WorkspaceMessage,
    shareable_workspace_messages: Set<(Id, Id)>,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        connection_connection_proof::never_invited_on_connection_for_workspace(
            row,
            local_endpoint,
            message.workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
    ensures
        !sync_shared_fact_proof::sync_visibility_selects_workspace_message(
            row,
            local_endpoint,
            message,
            shareable_workspace_messages,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
    connection_connection_proof::never_invited_connection_authorizes_no_workspace(
        row,
        local_endpoint,
        message.workspace_id,
        endpoint_memberships,
        scoped_bootstrap_invites,
    );
    sync_shared_fact_proof::not_authorized_connection_cannot_select_workspace_message(
        row,
        local_endpoint,
        message,
        shareable_workspace_messages,
        endpoint_memberships,
        scoped_bootstrap_invites,
    );
}

pub proof fn scoped_bootstrap_invite_is_intentional_memberless_sync_visibility(
    row: connection_connection_proof::ConnectionRow,
    local_endpoint: Id,
    message: sync_shared_fact_proof::WorkspaceMessage,
    shareable_workspace_messages: Set<(Id, Id)>,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        row.from_endpoint == local_endpoint,
        !endpoint_memberships.contains((message.workspace_id, row.to_endpoint)),
        scoped_bootstrap_invites.contains(
            (row.connection_id, row.to_endpoint, message.workspace_id),
        ),
        sync_shared_fact_proof::workspace_message_is_shareable(
            shareable_workspace_messages,
            message,
        ),
    ensures
        sync_shared_fact_proof::sync_visibility_selects_workspace_message(
            row,
            local_endpoint,
            message,
            shareable_workspace_messages,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
        !connection_connection_proof::never_invited_on_connection_for_workspace(
            row,
            local_endpoint,
            message.workspace_id,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
    connection_connection_proof::scoped_bootstrap_invite_authorizes_connection_workspace(
        row,
        local_endpoint,
        message.workspace_id,
        endpoint_memberships,
        scoped_bootstrap_invites,
    );
    sync_shared_fact_proof::shareable_and_authorized_connection_selects_workspace_message(
        row,
        local_endpoint,
        message,
        shareable_workspace_messages,
        endpoint_memberships,
        scoped_bootstrap_invites,
    );
}

pub proof fn malformed_local_orientation_cannot_receive_workspace_message_from_sync(
    row: connection_connection_proof::ConnectionRow,
    local_endpoint: Id,
    message: sync_shared_fact_proof::WorkspaceMessage,
    shareable_workspace_messages: Set<(Id, Id)>,
    endpoint_memberships: Set<(Id, Id)>,
    scoped_bootstrap_invites: Set<(Id, Id, Id)>,
)
    requires
        row.from_endpoint != local_endpoint,
        row.to_endpoint != local_endpoint,
    ensures
        !sync_shared_fact_proof::sync_visibility_selects_workspace_message(
            row,
            local_endpoint,
            message,
            shareable_workspace_messages,
            endpoint_memberships,
            scoped_bootstrap_invites,
        ),
{
    connection_connection_proof::connection_not_involving_local_endpoint_authorizes_no_workspace(
        row,
        local_endpoint,
        message.workspace_id,
        endpoint_memberships,
        scoped_bootstrap_invites,
    );
    sync_shared_fact_proof::not_authorized_connection_cannot_select_workspace_message(
        row,
        local_endpoint,
        message,
        shareable_workspace_messages,
        endpoint_memberships,
        scoped_bootstrap_invites,
    );
}

} // verus!
