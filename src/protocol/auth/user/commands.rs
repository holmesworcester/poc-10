//! Command constructors for user facts.
//!
//! User creation records a workspace member name and signing public key. This
//! file owns local construction, including the signed variant used when another
//! authority vouches for the user. Projection still validates that the user is
//! connected to a valid invite or authority chain before rows become visible.

use crate::core::command_context::CommandOutput;
use crate::core::crypto::{self, Ed25519PrivateKey, Ed25519PublicKey};
use crate::core::facts::{Fact, FactId, FactScope};

use super::fact::{UserFact, Username};
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
    let _ = input;
    Err("user facts must be signed by an invite authority".to_string())
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
    let signer_public_key = crypto::ed25519_public_key(&input.signer_private_key);
    let mut payload = UserFact {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        public_key,
        username: Username::new(&input.username).map_err(|err| format!("username: {err}"))?,
        signer_id: input.signer_id,
        signer_public_key,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let (_, signature) = crypto::ed25519_sign_canonical(
        &input.signer_private_key,
        &layout::signing_bytes(&payload)?,
    );
    payload.signature = signature;
    Ok(Fact::new(
        FactScope::Global,
        input.created_at_ms,
        layout::encode_fact(&payload)?,
    ))
}
