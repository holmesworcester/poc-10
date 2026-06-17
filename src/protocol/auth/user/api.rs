//! Command constructors for user facts.
//!
//! User creation records a workspace member name and signing public key. This
//! file owns local construction, including the authority-backed variant used
//! when another authority vouches for the user. Projection still validates that
//! the user is connected to a valid invite or authority chain before rows become
//! visible.

use crate::core::command::AuthoredFacts;
use crate::core::crypto::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::core::facts::{Fact, FactId};
use crate::protocol::auth;

use super::author;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUser {
    pub created_at_ms: u64,
    pub workspace_id: FactId,
    pub public_key: Ed25519PublicKey,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUserWithAuthority {
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

pub fn create(input: CreateUser) -> Result<AuthoredFacts<CreateUserReceipt>, String> {
    let fact = user_fact(&input)?;
    Ok(AuthoredFacts::new(CreateUserReceipt {
        user_id: fact.id,
        public_key: input.public_key,
        username: input.username,
    })
    .with_facts(vec![fact]))
}

pub fn create_with_authority(
    input: CreateUserWithAuthority,
) -> Result<AuthoredFacts<CreateUserReceipt>, String> {
    let public_key = crate::core::crypto::ed25519_public_key(&input.signer_private_key);
    let fact = authored_user_fact(&input, public_key)?;
    let signature = auth::signature::author::sign_fact(
        input.workspace_id,
        &fact,
        &input.signer_private_key,
        input.created_at_ms,
    )?;
    Ok(AuthoredFacts::new(CreateUserReceipt {
        user_id: fact.id,
        public_key,
        username: input.username,
    })
    .with_facts(vec![fact, signature]))
}

pub fn user_fact(input: &CreateUser) -> Result<Fact, String> {
    let _ = input;
    Err("user facts require signature evidence from an invite authority".to_string())
}

pub fn authored_user_fact(
    input: &CreateUserWithAuthority,
    public_key: Ed25519PublicKey,
) -> Result<Fact, String> {
    author::authored_user_fact(
        input.created_at_ms,
        input.workspace_id,
        public_key,
        &input.username,
        input.signer_id,
        input.signer_private_key,
    )
}
