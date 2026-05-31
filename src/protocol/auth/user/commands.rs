//! Command constructors for user facts.
//!
//! User creation records a workspace member name and signing public key. This
//! file owns local construction, including the signed variant used when another
//! authority vouches for the user. Projection still validates that the user is
//! connected to a valid invite or authority chain before rows become visible.

use crate::core::command_context::CommandOutput;
use crate::core::crypto::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::core::facts::{Fact, FactId};

use super::create;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUser {
    pub created_at_ms: u64,
    pub workspace_id: FactId,
    pub public_key: Ed25519PublicKey,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSignedUser {
    pub created_at_ms: u64,
    pub workspace_id: FactId,
    pub signer_id: FactId,
    pub signer_private_key: Ed25519PrivateKey,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUserReceipt {
    pub user_id: FactId,
    pub public_key: Ed25519PublicKey,
    pub username: String,
}

pub fn create(input: CreateUser) -> Result<CommandOutput<CreateUserReceipt>, String> {
    let fact = user_fact(&input)?;
    Ok(CommandOutput::new(CreateUserReceipt {
        user_id: fact.id,
        public_key: input.public_key,
        username: input.username,
    })
    .with_facts(vec![fact]))
}

pub fn create_signed(input: CreateSignedUser) -> Result<CommandOutput<CreateUserReceipt>, String> {
    let public_key = crate::core::crypto::ed25519_public_key(&input.signer_private_key);
    let fact = signed_user_fact(&input, public_key)?;
    Ok(CommandOutput::new(CreateUserReceipt {
        user_id: fact.id,
        public_key,
        username: input.username,
    })
    .with_facts(vec![fact]))
}

pub fn user_fact(input: &CreateUser) -> Result<Fact, String> {
    let _ = input;
    Err("user facts must be signed by an invite authority".to_string())
}

pub fn signed_user_fact(
    input: &CreateSignedUser,
    public_key: Ed25519PublicKey,
) -> Result<Fact, String> {
    create::signed_user_fact(
        input.created_at_ms,
        input.workspace_id,
        public_key,
        &input.username,
        input.signer_id,
        input.signer_private_key,
    )
}
