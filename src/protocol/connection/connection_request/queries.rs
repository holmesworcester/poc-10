//! Connection-mode trigger.
//!
//! `choose_connection_mode` is the pure, locally-checkable decision made at
//! connect time: can we open a *membership* connection to a target endpoint
//! without an invite? That is true exactly when we hold mutual `endpoint_shared`
//! membership with the target in some workspace (we are both admitted members)
//! and we have a learned reachable address for it. First contact is always
//! bootstrap (the peer cannot validate us yet); after a bootstrap sync both
//! sides hold mutual membership, so the next connect resolves to a membership
//! connection that needs no invite material and survives invite-link expiry.
//!
//! This reads only `endpoint_shared` membership and the connection-owned learned
//! address rows. It is side-effect free and never opens sockets.

use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::store::Store;

use crate::protocol::auth::endpoint::create::local_endpoint;
use crate::protocol::auth::endpoint_shared::queries::all_memberships;
use crate::protocol::connection::peer_address::queries::peer_address;

/// A membership connection we can open to a known peer without an invite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipConnectionPlan {
    pub workspace_id: FactId,
    /// Our own `endpoint_shared` fact id in that workspace (the membership
    /// witness the request carries).
    pub initiator_endpoint_shared_id: FactId,
    pub to_endpoint: FactId,
    pub addr: SocketAddr,
}

/// Decide whether a membership connection to `target_endpoint` is possible.
///
/// Returns `Some` iff we hold our own `endpoint_shared` and the target's
/// `endpoint_shared` in the same workspace (mutual membership) and we have a
/// learned address for the target. Otherwise `None`: the caller must bootstrap
/// from an invite instead.
pub fn choose_connection_mode(
    store: &Store,
    target_endpoint: FactId,
) -> Result<Option<MembershipConnectionPlan>, String> {
    let Some(local) = local_endpoint(store)? else {
        return Ok(None);
    };
    if target_endpoint == local.endpoint {
        return Ok(None);
    }

    let memberships = all_memberships(store)?;

    // Find a workspace where both the target and our own endpoint are admitted.
    for row in memberships
        .iter()
        .filter(|row| row.endpoint_id == target_endpoint)
    {
        let Some(local_membership) = memberships.iter().find(|other| {
            other.workspace_id == row.workspace_id && other.endpoint_id == local.endpoint
        }) else {
            continue;
        };
        let Some(addr) = peer_address(store, &target_endpoint)? else {
            continue;
        };
        return Ok(Some(MembershipConnectionPlan {
            workspace_id: row.workspace_id,
            initiator_endpoint_shared_id: local_membership.endpoint_shared_id,
            to_endpoint: target_endpoint,
            addr,
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    // The full transition — Bootstrap before mutual membership, Normal after a
    // bootstrap sync, and content reconnect without an invite — is covered by the
    // `cli_membership_connect_reconnects_known_peer_without_invite` black-box test.
    // Here we only pin the local guard: with no local endpoint identity there is
    // no membership connection to choose.
    #[test]
    fn no_local_endpoint_yields_no_membership_connection() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("store");
        assert_eq!(choose_connection_mode(&store, [9; 32]).expect("query"), None);
    }
}
