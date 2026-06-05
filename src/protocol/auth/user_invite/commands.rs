//! Command constructors for user-invite facts.
//!
//! User invites are the identity edge that lets a new user join a workspace.
//! Commands build either a raw invite with a supplied public key or a signed
//! invite when local secret material is available. Projection is still the
//! authority boundary: it decides whether the stated authority fact can invite
//! a user into the workspace.

use super::author;
use crate::core::command_context::CommandOutput;
use crate::core::crypto::{self, Ed25519PrivateKey, Ed25519PublicKey};
use crate::core::facts::{Fact, FactId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateUserInvite {
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: FactId,
    pub authority_fact_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateUserInviteWithSecret {
    pub created_at_ms: u64,
    pub workspace_id: FactId,
    pub authority_fact_id: FactId,
    pub signer_id: FactId,
    pub invite_private_key: Ed25519PrivateKey,
    pub signer_private_key: Ed25519PrivateKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateUserInviteReceipt {
    pub user_invite_id: FactId,
    pub public_key: Ed25519PublicKey,
}

pub fn create(input: CreateUserInvite) -> Result<CommandOutput<CreateUserInviteReceipt>, String> {
    let fact = user_invite_fact(input)?;
    Ok(CommandOutput::new(CreateUserInviteReceipt {
        user_invite_id: fact.id,
        public_key: input.public_key,
    })
    .with_facts(vec![fact]))
}

pub fn create_with_secret(
    input: CreateUserInviteWithSecret,
) -> Result<CommandOutput<CreateUserInviteReceipt>, String> {
    let create = CreateUserInvite {
        created_at_ms: input.created_at_ms,
        public_key: crypto::ed25519_public_key(&input.invite_private_key),
        workspace_id: input.workspace_id,
        authority_fact_id: input.authority_fact_id,
    };
    let fact = signed_user_invite_fact(create, input.signer_id, input.signer_private_key)?;
    Ok(CommandOutput::new(CreateUserInviteReceipt {
        user_invite_id: fact.id,
        public_key: create.public_key,
    })
    .with_facts(vec![fact]))
}

pub fn user_invite_fact(input: CreateUserInvite) -> Result<Fact, String> {
    let _ = input;
    Err("user_invite facts must be signed by their authority".to_string())
}

pub fn signed_user_invite_fact(
    input: CreateUserInvite,
    signer_id: FactId,
    signer_private_key: Ed25519PrivateKey,
) -> Result<Fact, String> {
    author::signed_user_invite_fact(
        input.created_at_ms,
        input.public_key,
        input.workspace_id,
        input.authority_fact_id,
        signer_id,
        signer_private_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_with_secret_derives_public_key_and_fact_id() {
        let private = [7; 32];
        let output = create_with_secret(CreateUserInviteWithSecret {
            created_at_ms: 5,
            workspace_id: [1; 32],
            authority_fact_id: [1; 32],
            signer_id: [1; 32],
            invite_private_key: private,
            signer_private_key: private,
        })
        .expect("create");

        assert_eq!(output.effects.facts.len(), 1);
        assert_eq!(output.receipt.user_invite_id, output.effects.facts[0].id);
        assert_eq!(
            output.receipt.public_key,
            crypto::ed25519_public_key(&private)
        );
    }
}
