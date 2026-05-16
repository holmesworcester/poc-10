//! Command constructors for local invite acceptance facts.

use crate::core::command_context::CommandOutput;
use crate::core::crypto::Ed25519PrivateKey;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::event_modules::identity_invite;

use super::fact::InviteAcceptedFact;
use super::layout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptInvite {
    pub created_at_ms: u64,
    pub accepted_endpoint_id: [u8; 32],
    pub bootstrap_secret: Ed25519PrivateKey,
    pub workspace_id: FactId,
    pub invite_event_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptInviteReceipt {
    pub invite_secret_event_id: FactId,
    pub invite_accepted_event_id: FactId,
    pub bootstrap_hash: FactId,
}

pub fn accept(input: AcceptInvite) -> Result<CommandOutput<AcceptInviteReceipt>, String> {
    validate_id("accepted_endpoint_id", &input.accepted_endpoint_id)?;
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("invite_event_id", &input.invite_event_id)?;

    let secret = identity_invite::fact::InviteSecretFact::scoped(
        input.bootstrap_secret,
        input.workspace_id,
        input.invite_event_id,
    );
    let secret_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms,
        identity_invite::layout::encode_fact(&secret)?,
    );

    let accepted = InviteAcceptedFact {
        workspace_id: input.workspace_id,
        invite_event_id: input.invite_event_id,
        invite_secret_event_id: secret_fact.id,
        bootstrap_hash: secret.bootstrap_hash,
        accepted_endpoint_id: input.accepted_endpoint_id,
    };
    let accepted_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms.saturating_add(1),
        layout::encode_fact(&accepted)?,
    );

    Ok(CommandOutput::new(AcceptInviteReceipt {
        invite_secret_event_id: secret_fact.id,
        invite_accepted_event_id: accepted_fact.id,
        bootstrap_hash: secret.bootstrap_hash,
    })
    .with_facts(vec![secret_fact, accepted_fact]))
}

fn validate_id(name: &str, id: &[u8; 32]) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::event_modules::identity_invite::layout as invite_layout;

    use super::*;

    #[test]
    fn accept_invite_creates_scoped_secret_and_acceptance_facts() {
        let output = accept(AcceptInvite {
            created_at_ms: 10,
            accepted_endpoint_id: [5; 32],
            bootstrap_secret: [7; 32],
            workspace_id: [1; 32],
            invite_event_id: [2; 32],
        })
        .expect("accept");

        assert_eq!(output.facts.len(), 2);
        assert_eq!(output.receipt.invite_secret_event_id, output.facts[0].id);
        assert_eq!(output.receipt.invite_accepted_event_id, output.facts[1].id);

        let secret = invite_layout::decode_fact(&output.facts[0].bytes).expect("decode secret");
        assert_eq!(secret.workspace_id, Some([1; 32]));
        assert_eq!(secret.invite_event_id, Some([2; 32]));
    }
}
