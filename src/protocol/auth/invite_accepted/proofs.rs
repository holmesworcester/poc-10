//! Verus proofs for the `protocol::auth::invite_accepted` fact family.
//!
//! Invite acceptance is local bootstrap evidence. Its producer proof exports
//! only the fact that a local, decoded, identity-scoped acceptance may publish
//! `auth_workspace_accepted` for its selected workspace.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {
pub mod verus_model {
    use vstd::prelude::*;

    pub open spec fn local_scope() -> int {
        0int
    }

    pub open spec fn global_scope() -> int {
        1int
    }

    pub open spec fn workspace_accepted_role() -> int {
        2int
    }

    #[derive(Copy, Clone)]
    pub struct SpecInviteAcceptedFact {
        pub fact_id: int,
        pub scope: int,
        pub workspace_id: int,
        pub decoded: bool,
        pub identity_scope: bool,
    }

    #[derive(Copy, Clone)]
    pub struct SpecWorkspaceAcceptedOffer {
        pub owner: int,
        pub role: int,
        pub scope: int,
        pub start_key: int,
        pub end_key: int,
        pub workspace_id: int,
    }

    pub open spec fn workspace_accepted_projector_offer(
        fact: SpecInviteAcceptedFact,
    ) -> SpecWorkspaceAcceptedOffer {
        SpecWorkspaceAcceptedOffer {
            owner: fact.fact_id,
            role: workspace_accepted_role(),
            scope: global_scope(),
            start_key: fact.workspace_id,
            end_key: fact.workspace_id,
            workspace_id: fact.workspace_id,
        }
    }

    pub open spec fn valid_workspace_accepted_offer(
        offer: SpecWorkspaceAcceptedOffer,
        fact: SpecInviteAcceptedFact,
        workspace_id: int,
    ) -> bool {
        fact.decoded
            && fact.scope == local_scope()
            && fact.identity_scope
            && fact.workspace_id == workspace_id
            && offer.owner == fact.fact_id
            && offer.role == workspace_accepted_role()
            && offer.scope == global_scope()
            && offer.start_key == workspace_id
            && offer.end_key == workspace_id
            && offer.workspace_id == workspace_id
    }

    pub proof fn theorem_workspace_accepted_projector_offer_is_valid(
        fact: SpecInviteAcceptedFact,
        workspace_id: int,
    )
        requires
            fact.decoded,
            fact.scope == local_scope(),
            fact.identity_scope,
            fact.workspace_id == workspace_id,
        ensures
            valid_workspace_accepted_offer(
                workspace_accepted_projector_offer(fact),
                fact,
                workspace_id,
            )
    {
    }
}
}
