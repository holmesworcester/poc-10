//! Verus proofs for the `protocol::auth::workspace` fact family.
//!
//! Workspace is the first complete projector proof set. It consumes trusted core
//! plumbing theorems plus producer theorems from `signature` and
//! `invite_accepted`, then proves the workspace projector's materialized row,
//! authority offer, and sync-share output predicates.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
#[path = "../../../core/proofs.rs"]
pub mod core_proofs;

#[cfg(verus_keep_ghost)]
#[path = "../invite_accepted/proofs.rs"]
pub mod invite_accepted_proofs;

#[cfg(verus_keep_ghost)]
#[path = "../signature/proofs.rs"]
pub mod signature_proofs;

#[cfg(verus_keep_ghost)]
verus! {
pub mod verus_model {
    use vstd::prelude::*;

    use super::core_proofs::verus_model as core;
    use super::invite_accepted_proofs::verus_model as accepted;
    use super::signature_proofs::verus_model as sig;

    pub open spec fn global_scope() -> int {
        1int
    }

    pub open spec fn auth_workspace_role() -> int {
        3int
    }

    pub open spec fn workspace_scope(workspace_id: int) -> int {
        workspace_id
    }

    #[derive(Copy, Clone)]
    pub struct SpecWorkspaceFact {
        pub fact_id: int,
        pub scope: int,
        pub public_key: int,
        pub decoded: bool,
        pub id_matches_bytes: bool,
    }

    #[derive(Copy, Clone)]
    pub struct SpecWorkspaceRow {
        pub workspace_id: int,
        pub public_key: int,
    }

    #[derive(Copy, Clone)]
    pub struct SpecWorkspaceOffer {
        pub owner: int,
        pub role: int,
        pub scope: int,
        pub start_key: int,
        pub end_key: int,
    }

    #[derive(Copy, Clone)]
    pub struct SpecWorkspaceSyncShare {
        pub workspace_id: int,
        pub owner_fact_id: int,
        pub context_have_len: int,
        pub context_have_slot_0: int,
        pub is_upsert: bool,
    }

    #[derive(Copy, Clone)]
    pub struct SpecWorkspaceMaterializedOutput {
        pub core_output: core::SpecProjectionOutput,
        pub row: SpecWorkspaceRow,
        pub offer: SpecWorkspaceOffer,
        pub sync_share: SpecWorkspaceSyncShare,
        pub no_waiting_needs: bool,
        pub no_extra_effects: bool,
    }

    pub open spec fn workspace_signature_need(
        workspace: SpecWorkspaceFact,
    ) -> core::SpecContextNeed {
        core::SpecContextNeed {
            owner: workspace.fact_id,
            role: sig::signature_proof_role(),
            scope: workspace_scope(workspace.fact_id),
            start_key: sig::signature_selector(workspace.fact_id, workspace.public_key),
            end_key: sig::signature_selector(workspace.fact_id, workspace.public_key),
        }
    }

    pub open spec fn workspace_accepted_need(
        workspace: SpecWorkspaceFact,
    ) -> core::SpecContextNeed {
        core::SpecContextNeed {
            owner: workspace.fact_id,
            role: accepted::workspace_accepted_role(),
            scope: global_scope(),
            start_key: workspace.fact_id,
            end_key: workspace.fact_id,
        }
    }

    pub open spec fn workspace_offer(workspace: SpecWorkspaceFact) -> SpecWorkspaceOffer {
        SpecWorkspaceOffer {
            owner: workspace.fact_id,
            role: auth_workspace_role(),
            scope: global_scope(),
            start_key: workspace.fact_id,
            end_key: workspace.fact_id,
        }
    }

    pub open spec fn workspace_row(workspace: SpecWorkspaceFact) -> SpecWorkspaceRow {
        SpecWorkspaceRow {
            workspace_id: workspace.fact_id,
            public_key: workspace.public_key,
        }
    }

    pub open spec fn workspace_sync_share(
        workspace: SpecWorkspaceFact,
        signature_fact: sig::SpecSignatureFact,
    ) -> SpecWorkspaceSyncShare {
        SpecWorkspaceSyncShare {
            workspace_id: workspace.fact_id,
            owner_fact_id: workspace.fact_id,
            context_have_len: 1int,
            context_have_slot_0: signature_fact.fact_id,
            is_upsert: true,
        }
    }

    pub open spec fn workspace_core_materialized_output(
        workspace: SpecWorkspaceFact,
    ) -> core::SpecProjectionOutput {
        core::SpecProjectionOutput {
            current_fact_id: workspace.fact_id,
            all_output_owners_are_self: true,
            purges_only_current_fact: true,
            has_materialized_rows: true,
            has_materialized_offers: true,
            has_materialized_intents: true,
            has_materialized_facts: false,
            has_time_wakes: false,
            has_purges: false,
        }
    }

    pub open spec fn workspace_materialized_output(
        workspace: SpecWorkspaceFact,
        signature_fact: sig::SpecSignatureFact,
    ) -> SpecWorkspaceMaterializedOutput {
        SpecWorkspaceMaterializedOutput {
            core_output: workspace_core_materialized_output(workspace),
            row: workspace_row(workspace),
            offer: workspace_offer(workspace),
            sync_share: workspace_sync_share(workspace, signature_fact),
            no_waiting_needs: true,
            no_extra_effects: true,
        }
    }

    pub open spec fn workspace_output_is_canonical(
        workspace: SpecWorkspaceFact,
        signature_fact: sig::SpecSignatureFact,
        accepted_fact: accepted::SpecInviteAcceptedFact,
        output: SpecWorkspaceMaterializedOutput,
    ) -> bool {
        output.core_output.current_fact_id == workspace.fact_id
            && output.core_output.all_output_owners_are_self
            && output.core_output.purges_only_current_fact
            && output.core_output.has_materialized_rows
            && output.core_output.has_materialized_offers
            && output.core_output.has_materialized_intents
            && !output.core_output.has_materialized_facts
            && !output.core_output.has_time_wakes
            && !output.core_output.has_purges
            && output.no_waiting_needs
            && output.no_extra_effects
            && output.row.workspace_id == workspace.fact_id
            && output.row.public_key == workspace.public_key
            && output.offer.owner == workspace.fact_id
            && output.offer.role == auth_workspace_role()
            && output.offer.scope == global_scope()
            && output.offer.start_key == workspace.fact_id
            && output.offer.end_key == workspace.fact_id
            && output.sync_share.workspace_id == workspace.fact_id
            && output.sync_share.owner_fact_id == workspace.fact_id
            && output.sync_share.context_have_len == 1int
            && output.sync_share.context_have_slot_0 == signature_fact.fact_id
            && output.sync_share.context_have_slot_0 != accepted_fact.fact_id
            && output.sync_share.is_upsert
    }

    pub open spec fn valid_workspace_row(
        row: SpecWorkspaceRow,
        workspace: SpecWorkspaceFact,
    ) -> bool {
        workspace.decoded
            && workspace.id_matches_bytes
            && row.workspace_id == workspace.fact_id
            && row.public_key == workspace.public_key
    }

    pub open spec fn valid_workspace_offer(
        offer: SpecWorkspaceOffer,
        workspace: SpecWorkspaceFact,
    ) -> bool {
        offer.owner == workspace.fact_id
            && offer.role == auth_workspace_role()
            && offer.scope == global_scope()
            && offer.start_key == workspace.fact_id
            && offer.end_key == workspace.fact_id
    }

    pub open spec fn valid_workspace_sync_share(
        sync_share: SpecWorkspaceSyncShare,
        workspace: SpecWorkspaceFact,
        signature_fact: sig::SpecSignatureFact,
        accepted_fact: accepted::SpecInviteAcceptedFact,
    ) -> bool {
        sync_share.workspace_id == workspace.fact_id
            && sync_share.owner_fact_id == workspace.fact_id
            && sync_share.context_have_len == 1int
            && sync_share.context_have_slot_0 == signature_fact.fact_id
            && sync_share.context_have_slot_0 != accepted_fact.fact_id
            && sync_share.is_upsert
    }

    pub open spec fn valid_workspace_authority_context(
        workspace: SpecWorkspaceFact,
        signature_fact: sig::SpecSignatureFact,
        accepted_fact: accepted::SpecInviteAcceptedFact,
    ) -> bool {
        sig::valid_signature_proof_offer(
            sig::signature_projector_offer(signature_fact),
            signature_fact,
            workspace.fact_id,
            workspace.fact_id,
            workspace.public_key,
        )
            && accepted::valid_workspace_accepted_offer(
                accepted::workspace_accepted_projector_offer(accepted_fact),
                accepted_fact,
                workspace.fact_id,
            )
    }

    pub open spec fn workspace_authority_inputs(
        workspace: SpecWorkspaceFact,
        signature_match: core::SpecMatchedContext,
        accepted_match: core::SpecMatchedContext,
        signature_fact: sig::SpecSignatureFact,
        accepted_fact: accepted::SpecInviteAcceptedFact,
    ) -> bool {
        workspace.decoded
            && workspace.id_matches_bytes
            && workspace.scope == global_scope()
            && signature_fact.decoded
            && signature_fact.signature_verified
            && signature_fact.scope == workspace_scope(workspace.fact_id)
            && signature_fact.workspace_scope == workspace_scope(workspace.fact_id)
            && signature_fact.workspace_id == workspace.fact_id
            && signature_fact.target_fact_id == workspace.fact_id
            && signature_fact.signer_public_key == workspace.public_key
            && signature_match.payload_fact_id == signature_fact.fact_id
            && accepted_fact.decoded
            && accepted_fact.scope == accepted::local_scope()
            && accepted_fact.identity_scope
            && accepted_fact.workspace_id == workspace.fact_id
            && accepted_match.payload_fact_id == accepted_fact.fact_id
    }

    pub open spec fn workspace_context_matches_authority_needs(
        workspace: SpecWorkspaceFact,
        signature_match: core::SpecMatchedContext,
        accepted_match: core::SpecMatchedContext,
    ) -> bool {
        core::matched_payloads_are_offer_owner_facts(signature_match)
            && core::matcher_preserves_role_scope_selector(
                workspace_signature_need(workspace),
                signature_match,
            )
            && core::matched_payloads_are_offer_owner_facts(accepted_match)
            && core::matcher_preserves_role_scope_selector(
                workspace_accepted_need(workspace),
                accepted_match,
            )
    }

    pub open spec fn workspace_projector_materializes(
        graph: core::SpecPipelineGraph,
        ctx: core::SpecProjectionContext,
        workspace: SpecWorkspaceFact,
        signature_match: core::SpecMatchedContext,
        accepted_match: core::SpecMatchedContext,
        signature_fact: sig::SpecSignatureFact,
        accepted_fact: accepted::SpecInviteAcceptedFact,
        output: SpecWorkspaceMaterializedOutput,
    ) -> bool {
        core::projection_context_sound(ctx, graph)
            && workspace_context_matches_authority_needs(
                workspace,
                signature_match,
                accepted_match,
            )
            && workspace_authority_inputs(
                workspace,
                signature_match,
                accepted_match,
                signature_fact,
                accepted_fact,
            )
            && workspace_output_is_canonical(workspace, signature_fact, accepted_fact, output)
    }

    pub open spec fn workspace_materialization_safety_bar(
        workspace: SpecWorkspaceFact,
        signature_match: core::SpecMatchedContext,
        accepted_match: core::SpecMatchedContext,
        signature_fact: sig::SpecSignatureFact,
        accepted_fact: accepted::SpecInviteAcceptedFact,
        output: SpecWorkspaceMaterializedOutput,
    ) -> bool {
        workspace_authority_inputs(
            workspace,
            signature_match,
            accepted_match,
            signature_fact,
            accepted_fact,
        )
            && workspace_context_matches_authority_needs(
                workspace,
                signature_match,
                accepted_match,
            )
            && valid_workspace_authority_context(workspace, signature_fact, accepted_fact)
            && workspace_output_is_canonical(workspace, signature_fact, accepted_fact, output)
            && valid_workspace_materialized_output(
                workspace,
                signature_fact,
                accepted_fact,
                output,
            )
    }

    pub open spec fn valid_workspace_materialized_output(
        workspace: SpecWorkspaceFact,
        signature_fact: sig::SpecSignatureFact,
        accepted_fact: accepted::SpecInviteAcceptedFact,
        output: SpecWorkspaceMaterializedOutput,
    ) -> bool {
        workspace.scope == global_scope()
            && valid_workspace_authority_context(workspace, signature_fact, accepted_fact)
            && core::projection_output_owners_are_self(output.core_output, workspace.fact_id)
            && core::purges_are_self_only(output.core_output, workspace.fact_id)
            && output.no_waiting_needs
            && output.no_extra_effects
            && valid_workspace_row(output.row, workspace)
            && valid_workspace_offer(output.offer, workspace)
            && valid_workspace_sync_share(output.sync_share, workspace, signature_fact, accepted_fact)
    }

    pub proof fn theorem_workspace_materialization_only_if(
        graph: core::SpecPipelineGraph,
        ctx: core::SpecProjectionContext,
        workspace: SpecWorkspaceFact,
        signature_match: core::SpecMatchedContext,
        accepted_match: core::SpecMatchedContext,
        signature_fact: sig::SpecSignatureFact,
        accepted_fact: accepted::SpecInviteAcceptedFact,
        output: SpecWorkspaceMaterializedOutput,
    )
        requires workspace_projector_materializes(
            graph,
            ctx,
            workspace,
            signature_match,
            accepted_match,
            signature_fact,
            accepted_fact,
            output,
        )
        ensures
            workspace_materialization_safety_bar(
                workspace,
                signature_match,
                accepted_match,
                signature_fact,
                accepted_fact,
                output,
            )
    {
        core::theorem_projection_context_sound(ctx, graph);
        core::theorem_matched_payloads_are_offer_owner_facts(signature_match);
        core::theorem_matcher_preserves_role_scope_selector(
            workspace_signature_need(workspace),
            signature_match,
        );
        core::theorem_matched_payloads_are_offer_owner_facts(accepted_match);
        core::theorem_matcher_preserves_role_scope_selector(
            workspace_accepted_need(workspace),
            accepted_match,
        );
        core::theorem_projection_output_owners_are_self(output.core_output, workspace.fact_id);
        core::theorem_purges_are_self_only(output.core_output, workspace.fact_id);
        sig::theorem_signature_projector_offer_is_valid(
            signature_fact,
            workspace.fact_id,
            workspace.fact_id,
            workspace.public_key,
        );
        accepted::theorem_workspace_accepted_projector_offer_is_valid(
            accepted_fact,
            workspace.fact_id,
        );
    }

    pub proof fn theorem_workspace_projector_materializes_iff_safety_shape(
        graph: core::SpecPipelineGraph,
        ctx: core::SpecProjectionContext,
        workspace: SpecWorkspaceFact,
        signature_match: core::SpecMatchedContext,
        accepted_match: core::SpecMatchedContext,
        signature_fact: sig::SpecSignatureFact,
        accepted_fact: accepted::SpecInviteAcceptedFact,
        output: SpecWorkspaceMaterializedOutput,
    )
        ensures
            workspace_projector_materializes(
                graph,
                ctx,
                workspace,
                signature_match,
                accepted_match,
                signature_fact,
                accepted_fact,
                output,
            ) == (
                core::projection_context_sound(ctx, graph)
                && workspace_context_matches_authority_needs(
                    workspace,
                    signature_match,
                    accepted_match,
                )
                && workspace_authority_inputs(
                    workspace,
                    signature_match,
                    accepted_match,
                    signature_fact,
                    accepted_fact,
                )
                && workspace_output_is_canonical(workspace, signature_fact, accepted_fact, output)
            )
    {
    }

    pub proof fn theorem_workspace_materialized_output(
        graph: core::SpecPipelineGraph,
        ctx: core::SpecProjectionContext,
        workspace: SpecWorkspaceFact,
        signature_match: core::SpecMatchedContext,
        accepted_match: core::SpecMatchedContext,
        signature_fact: sig::SpecSignatureFact,
        accepted_fact: accepted::SpecInviteAcceptedFact,
        output: SpecWorkspaceMaterializedOutput,
    )
        requires workspace_projector_materializes(
            graph,
            ctx,
            workspace,
            signature_match,
            accepted_match,
            signature_fact,
            accepted_fact,
            output,
        )
        ensures
            valid_workspace_materialized_output(
                workspace,
                signature_fact,
                accepted_fact,
                output,
            )
    {
        theorem_workspace_materialization_only_if(
            graph,
            ctx,
            workspace,
            signature_match,
            accepted_match,
            signature_fact,
            accepted_fact,
            output,
        );
    }
}
}
