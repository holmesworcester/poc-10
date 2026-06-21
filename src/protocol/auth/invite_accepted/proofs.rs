//! Proof predicates for the `protocol::auth::invite_accepted` fact family.
//!
//! Keep family-local proof work here: canonical layout, fact-boundary
//! authentication, context proof obligations, projection offers, and row
//! materialization. Cross-family or core substrate proofs belong outside this
//! fact-family module.

use crate::core::context::ContextOffer;
use crate::core::facts::{Fact, FactId, FactScope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidWorkspaceAcceptedOffer;

/// A workspace-accepted offer is local bootstrap evidence. It is valid only
/// when the offer owner payload is a local `invite_accepted` fact whose body
/// selects the same workspace and whose identity scope permits workspace
/// materialization to continue.
pub fn valid_workspace_accepted_offer(
    offer: &ContextOffer,
    payload: &Fact,
    workspace_id: FactId,
) -> bool {
    if payload.scope != FactScope::Local {
        return false;
    }
    if offer != &super::workspace_accepted_offer(payload.id, workspace_id) {
        return false;
    }
    let accepted = match super::decode_fact_payload(payload.body()) {
        Ok(accepted) => accepted,
        Err(_) => return false,
    };
    accepted.workspace_id == workspace_id && accepted.identity_scope
}

pub fn theorem_valid_workspace_accepted_offer(
    offer: &ContextOffer,
    payload: &Fact,
    workspace_id: FactId,
) -> Result<ValidWorkspaceAcceptedOffer, String> {
    valid_workspace_accepted_offer(offer, payload, workspace_id)
        .then_some(ValidWorkspaceAcceptedOffer)
        .ok_or_else(|| "workspace accepted offer is not valid local identity evidence".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::auth::invite_secret::fact::bootstrap_secret_hash;

    #[test]
    fn workspace_accepted_certificate_requires_local_identity_scoped_payload() {
        let workspace_id = [1; 32];
        let (_accepted, payload) = super::super::author::accepted_fact(
            workspace_id,
            [2; 32],
            bootstrap_secret_hash(&[7; 32]),
            [7; 32],
            [3; 32],
            [4; 32],
            "127.0.0.1:41000".parse().unwrap(),
            None,
            EndpointRole::Device,
            true,
            123,
        )
        .expect("accepted fact");
        let offer = super::super::workspace_accepted_offer(payload.id, workspace_id);

        theorem_valid_workspace_accepted_offer(&offer, &payload, workspace_id)
            .expect("valid workspace accepted offer");

        let wrong_scope_payload = Fact {
            scope: FactScope::Global,
            ..payload.clone()
        };
        assert!(!valid_workspace_accepted_offer(
            &offer,
            &wrong_scope_payload,
            workspace_id,
        ));
    }
}
