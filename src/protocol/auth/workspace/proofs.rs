//! Proof predicates for the `protocol::auth::workspace` fact family.
//!
//! Keep family-local proof work here: canonical layout, fact-boundary
//! authentication, context proof obligations, projection offers, and row
//! materialization. Cross-family or core substrate proofs belong outside this
//! fact-family module.

use std::collections::BTreeSet;

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::{verify_fact_id, Fact, FactId, FactScope};
use crate::core::intents::{Intent, RowMutation};
use crate::core::project_fact::{ProjectionContext, ProjectionOutput};
use crate::protocol::auth::{invite_accepted, signature};
use crate::protocol::sync::share_fact_with_sync::{self, SyncShareState};

use super::fact::WorkspaceFact;

pub const WORKSPACE_PROJECTOR_THREAT_INVARIANTS: &[&str] =
    &["TM-M1", "TM-M2", "TM-M3", "TM-C2", "TM-C3", "TM-I4"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceWaitingProof {
    pub workspace_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceMaterializedProof {
    pub workspace_id: FactId,
    pub signature_context_have: Vec<FactId>,
    pub covered_threat_invariants: &'static [&'static str],
}

/// A workspace row is valid when it is exactly the row builder output for the
/// projected workspace fact id and decoded workspace payload.
pub fn valid_workspace_row(
    mutation: &RowMutation,
    workspace_id: FactId,
    workspace: &WorkspaceFact,
) -> bool {
    mutation == &RowMutation::InsertValues(super::workspace_insert(workspace_id, workspace))
}

/// The root workspace authority offer is global, owner-scoped to the workspace
/// fact, and keyed exactly by that workspace id.
pub fn valid_workspace_offer(offer: &ContextOffer, workspace_id: FactId) -> bool {
    offer.owner == workspace_id
        && offer.role.as_str() == "auth_workspace"
        && offer.scope == FactScope::Global
        && offer.start_key.as_bytes() == workspace_id
        && offer.end_key.as_bytes() == workspace_id
}

/// Workspace sync sharing is valid only for the workspace fact itself, with
/// dependency context limited to non-local signature evidence. The local
/// invite-accepted fact that admitted the workspace must never travel as sync
/// context.
pub fn valid_workspace_sync_share_intent(
    intent: &Intent,
    workspace_fact: &Fact,
    expected_context_have: &[FactId],
    forbidden_context_fact_ids: &[FactId],
) -> bool {
    let shared = match share_fact_with_sync::decode_share_fact_with_sync(intent) {
        Ok(shared) => shared,
        Err(_) => return false,
    };
    let mut expected_context_have = expected_context_have.to_vec();
    expected_context_have.sort();
    expected_context_have.dedup();
    let mut expected_context_fact_ids = Vec::with_capacity(1 + expected_context_have.len());
    expected_context_fact_ids.push(workspace_fact.id);
    expected_context_fact_ids.extend(expected_context_have.iter().copied());
    shared.workspace_id == workspace_fact.id
        && shared.owner_fact_id == workspace_fact.id
        && shared.timestamp_ms == workspace_fact.timestamp
        && shared.state == SyncShareState::Upsert
        && shared.context_have == expected_context_have
        && intent.context_fact_ids == expected_context_fact_ids
        && forbidden_context_fact_ids
            .iter()
            .all(|id| !shared.context_have.contains(id) && !intent.context_fact_ids.contains(id))
}

pub fn theorem_workspace_waits_for_authority_context(
    workspace_fact: &Fact,
    output: &ProjectionOutput,
) -> Result<WorkspaceWaitingProof, String> {
    let workspace = decoded_verified_workspace(workspace_fact)?;
    if workspace_fact.scope != FactScope::Global {
        return Err("workspace waiting proof requires a global workspace fact".to_string());
    }
    crate::core::proofs::theorem_projection_output_owners_are_self(output, workspace_fact.id)?;
    crate::core::proofs::theorem_purges_are_self_only(output, workspace_fact.id)?;
    crate::core::proofs::theorem_no_materialized_output(output)?;

    let signature_need = workspace_signature_need(workspace_fact.id, &workspace)?;
    let accepted_need =
        invite_accepted::workspace_accepted_need(workspace_fact.id, workspace_fact.id);
    let expected_needs = [&signature_need, &accepted_need];
    if output.needs.len() != expected_needs.len()
        || !expected_needs
            .iter()
            .all(|expected| output.needs.contains(expected))
    {
        return Err("workspace waiting output does not publish stable authority needs".to_string());
    }

    Ok(WorkspaceWaitingProof {
        workspace_id: workspace_fact.id,
    })
}

pub fn theorem_workspace_materialized_output(
    workspace_fact: &Fact,
    context: &ProjectionContext,
    output: &ProjectionOutput,
) -> Result<WorkspaceMaterializedProof, String> {
    let workspace = decoded_verified_workspace(workspace_fact)?;
    if workspace_fact.scope != FactScope::Global {
        return Err("workspace materialization requires a global workspace fact".to_string());
    }

    let signature_need = workspace_signature_need(workspace_fact.id, &workspace)?;
    let accepted_need =
        invite_accepted::workspace_accepted_need(workspace_fact.id, workspace_fact.id);
    crate::core::proofs::theorem_projection_context_sound(
        context,
        &[signature_need.clone(), accepted_need.clone()],
    )?;
    crate::core::proofs::theorem_projection_output_owners_are_self(output, workspace_fact.id)?;
    crate::core::proofs::theorem_purges_are_self_only(output, workspace_fact.id)?;

    let signature_payload_ids =
        prove_signature_context(context, &signature_need, workspace_fact.id, &workspace)?;
    let accepted_payload =
        prove_workspace_accepted_context(context, &accepted_need, workspace_fact.id)?;

    if !output.needs.is_empty() {
        return Err("materialized workspace output must not keep authority needs".to_string());
    }
    if output.offers.len() != 1 || !valid_workspace_offer(&output.offers[0], workspace_fact.id) {
        return Err("workspace output does not publish the valid auth_workspace offer".to_string());
    }
    if output.effects.row_mutations.len() != 1
        || !valid_workspace_row(
            &output.effects.row_mutations[0],
            workspace_fact.id,
            &workspace,
        )
    {
        return Err("workspace output does not insert the valid workspace row".to_string());
    }
    if output.effects.intents.len() != 1
        || !valid_workspace_sync_share_intent(
            &output.effects.intents[0],
            workspace_fact,
            &signature_payload_ids,
            &[accepted_payload.id],
        )
    {
        return Err("workspace output does not emit the valid sync-share intent".to_string());
    }
    if !output.time_wakes.is_empty()
        || !output.effects.facts.is_empty()
        || !output.effects.priority_facts.is_empty()
        || !output.effects.incoming_facts.is_empty()
        || !output.effects.incoming_fact_metadata.is_empty()
        || !output.effects.purged_facts.is_empty()
        || !output.effects.local_intents.is_empty()
        || output.effects.rebuild_derived_state
    {
        return Err(
            "workspace output contains effects outside the workspace projector contract"
                .to_string(),
        );
    }

    Ok(WorkspaceMaterializedProof {
        workspace_id: workspace_fact.id,
        signature_context_have: signature_payload_ids,
        covered_threat_invariants: WORKSPACE_PROJECTOR_THREAT_INVARIANTS,
    })
}

fn decoded_verified_workspace(workspace_fact: &Fact) -> Result<WorkspaceFact, String> {
    verify_fact_id(workspace_fact)?;
    super::decode_fact_payload(workspace_fact.body())
}

fn workspace_signature_need(
    workspace_id: FactId,
    workspace: &WorkspaceFact,
) -> Result<ContextNeed, String> {
    signature::project::signature_proof_need(
        workspace_id,
        super::scope(workspace_id),
        workspace_id,
        workspace.public_key,
    )
}

fn prove_signature_context(
    context: &ProjectionContext,
    need: &ContextNeed,
    workspace_id: FactId,
    workspace: &WorkspaceFact,
) -> Result<Vec<FactId>, String> {
    let mut ids = BTreeSet::new();
    for (offer, payload) in context.matched_payloads_for(need) {
        signature::proofs::theorem_valid_signature_proof_offer(
            offer,
            payload,
            workspace_id,
            workspace_id,
            workspace.public_key,
        )?;
        ids.insert(payload.id);
    }
    if ids.is_empty() {
        return Err("workspace materialization requires signature context".to_string());
    }
    Ok(ids.into_iter().collect())
}

fn prove_workspace_accepted_context<'a>(
    context: &'a ProjectionContext,
    need: &ContextNeed,
    workspace_id: FactId,
) -> Result<&'a Fact, String> {
    let Some(payload) = context.payload_for_checked(need, "workspace accepted proof")? else {
        return Err("workspace materialization requires local accepted context".to_string());
    };
    let offer = context
        .matched_payloads_for(need)
        .find_map(|(offer, candidate)| (candidate.id == payload.id).then_some(offer))
        .ok_or_else(|| "workspace accepted payload has no matching offer".to_string())?;
    invite_accepted::proofs::theorem_valid_workspace_accepted_offer(offer, payload, workspace_id)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::project_fact::{MatchedContext, Projector};
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::auth::invite_secret;

    #[test]
    fn workspace_projector_materialized_output_has_threat_model_certificate() {
        let fact = super::super::author::create_workspace(123_000, [9; 32], "Runtime")
            .expect("workspace fact");
        let accepted = accepted_fact(fact.id, fact.id, 124_000);
        let context = accepted_context(fact.id, &accepted);
        let output = super::super::project::WorkspaceProjector::new()
            .project(&fact, &context)
            .expect("project workspace");

        let proof = theorem_workspace_materialized_output(&fact, &context, &output)
            .expect("workspace output proof");

        assert_eq!(proof.workspace_id, fact.id);
        assert_eq!(
            proof.covered_threat_invariants,
            WORKSPACE_PROJECTOR_THREAT_INVARIANTS
        );
    }

    #[test]
    fn workspace_projector_waiting_output_has_no_materialization_certificate() {
        let fact = super::super::author::create_workspace(123_000, [9; 32], "Runtime")
            .expect("workspace fact");
        let output = super::super::project::WorkspaceProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project workspace without context");

        theorem_workspace_waits_for_authority_context(&fact, &output)
            .expect("workspace waiting proof");
    }

    #[test]
    fn workspace_proof_rejects_sync_share_that_includes_local_acceptance() {
        let fact = super::super::author::create_workspace(123_000, [9; 32], "Runtime")
            .expect("workspace fact");
        let accepted = accepted_fact(fact.id, fact.id, 124_000);
        let context = accepted_context(fact.id, &accepted);
        let mut output = super::super::project::WorkspaceProjector::new()
            .project(&fact, &context)
            .expect("project workspace");
        output.effects.intents = vec![share_fact_with_sync::share_fact_with_sync_intent_for_fact(
            fact.id,
            fact.id,
            fact.timestamp,
            vec![accepted.id],
        )];

        let err = theorem_workspace_materialized_output(&fact, &context, &output)
            .expect_err("local accepted fact must not be sync context");
        assert!(err.contains("valid sync-share intent"), "{err}");
    }

    fn accepted_fact(workspace_id: FactId, invite_fact_id: FactId, created_at_ms: u64) -> Fact {
        let (_accepted, accepted_fact) = invite_accepted::author::accepted_fact(
            workspace_id,
            invite_fact_id,
            invite_secret::fact::bootstrap_secret_hash(&[7; 32]),
            [7; 32],
            [5; 32],
            [6; 32],
            "127.0.0.1:41000".parse().unwrap(),
            None,
            EndpointRole::Device,
            true,
            created_at_ms + 1,
        )
        .expect("accepted fact");
        accepted_fact
    }

    fn accepted_context(workspace_id: FactId, accepted: &Fact) -> ProjectionContext {
        let need = invite_accepted::workspace_accepted_need(workspace_id, workspace_id);
        let offer = invite_accepted::workspace_accepted_offer(accepted.id, workspace_id);
        ProjectionContext::from_matches(vec![
            signature_match(workspace_id),
            MatchedContext {
                need,
                offer,
                payload: accepted.clone(),
            },
        ])
    }

    fn signature_match(workspace_id: FactId) -> MatchedContext {
        let private_key = [9; 32];
        let signer_public_key = crate::core::crypto::ed25519_public_key(&private_key);
        let scope = super::super::scope(workspace_id);
        let signature =
            signature::author::create_signature(workspace_id, workspace_id, &private_key, 123_000)
                .expect("workspace signature fact");
        MatchedContext {
            need: signature::project::signature_proof_need(
                workspace_id,
                scope.clone(),
                workspace_id,
                signer_public_key,
            )
            .expect("signature need"),
            offer: signature::project::signature_proof_offer(
                signature.id,
                scope,
                workspace_id,
                signer_public_key,
            )
            .expect("signature offer"),
            payload: signature,
        }
    }
}
