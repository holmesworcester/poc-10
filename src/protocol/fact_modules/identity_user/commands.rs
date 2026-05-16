//! Command constructors for user facts.

use crate::core::command_context::CommandOutput;
use crate::core::crypto::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::fact_modules::signed_fact;

use super::fact::UserFact;
use super::layout;

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
    if input.workspace_id == [0; 32] {
        return Err("user workspace_id cannot be empty".to_string());
    }
    if input.public_key == [0; 32] {
        return Err("user public_key cannot be empty".to_string());
    }
    if input.username.trim().is_empty() {
        return Err("username must not be empty".to_string());
    }
    let payload = UserFact {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        public_key: input.public_key,
        username: input.username.clone(),
    };
    Ok(Fact::new(
        FactScope::Global,
        input.created_at_ms,
        layout::encode_fact(&payload)?,
    ))
}

pub fn signed_user_fact(
    input: &CreateSignedUser,
    public_key: Ed25519PublicKey,
) -> Result<Fact, String> {
    if input.workspace_id == [0; 32] {
        return Err("user workspace_id cannot be empty".to_string());
    }
    if input.signer_id == [0; 32] {
        return Err("user signer_id cannot be empty".to_string());
    }
    if public_key == [0; 32] {
        return Err("user public_key cannot be empty".to_string());
    }
    if input.username.trim().is_empty() {
        return Err("username must not be empty".to_string());
    }
    let payload = UserFact {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        public_key,
        username: input.username.clone(),
    };
    let bytes = signed_fact::create::sign_payload_bytes(
        input.signer_id,
        &input.signer_private_key,
        layout::encode_fact(&payload)?,
    )?;
    Ok(Fact::new(FactScope::Global, input.created_at_ms, bytes))
}
