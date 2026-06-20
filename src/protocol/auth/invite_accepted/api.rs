//! Command constructors for accepting an invite link locally.
//!
//! Invite acceptance produces a single retained local acceptance fact. That
//! fact carries the invite-link bootstrap context needed to replay workspace
//! admission and to let live connection maintenance rebuild bootstrap attempts.

use crate::core::command::AuthoredFacts;
use crate::core::crypto::Ed25519PrivateKey;
use crate::core::facts::FactId;
use crate::protocol::auth;
use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
use std::net::SocketAddr;

use super::author;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptInvite {
    pub created_at_ms: u64,
    pub accepted_endpoint_id: [u8; 32],
    pub bootstrap_secret: Ed25519PrivateKey,
    pub bootstrap_endpoint_id: [u8; 32],
    pub bootstrap_addr: SocketAddr,
    pub workspace_id: FactId,
    pub invite_fact_id: FactId,
    pub user_authority_fact_id: Option<FactId>,
    pub endpoint_role: EndpointRole,
    pub identity_scope: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptInviteReceipt {
    pub invite_accepted_fact_id: FactId,
    pub bootstrap_hash: FactId,
}

pub fn accept(input: AcceptInvite) -> Result<AuthoredFacts<AcceptInviteReceipt>, String> {
    validate_id("accepted_endpoint_id", &input.accepted_endpoint_id)?;
    validate_id("bootstrap_endpoint_id", &input.bootstrap_endpoint_id)?;
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("invite_fact_id", &input.invite_fact_id)?;
    if input.bootstrap_secret == [0; 32] {
        return Err("bootstrap_secret cannot be empty".to_string());
    }

    let bootstrap_hash = auth::invite_secret::fact::bootstrap_secret_hash(&input.bootstrap_secret);
    let (_accepted, accepted_fact) = author::accepted_fact(
        input.workspace_id,
        input.invite_fact_id,
        bootstrap_hash,
        input.bootstrap_secret,
        input.accepted_endpoint_id,
        input.bootstrap_endpoint_id,
        input.bootstrap_addr,
        input.user_authority_fact_id,
        input.endpoint_role,
        input.identity_scope,
        input.created_at_ms,
    )?;

    Ok(AuthoredFacts::new(AcceptInviteReceipt {
        invite_accepted_fact_id: accepted_fact.id,
        bootstrap_hash,
    })
    .with_facts(vec![accepted_fact]))
}

fn validate_id(name: &str, id: &[u8; 32]) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

// Tests.
// Single test: invite acceptance produces exactly one acceptance fact.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_invite_creates_only_acceptance_fact() {
        let output = accept(AcceptInvite {
            created_at_ms: 10,
            accepted_endpoint_id: [5; 32],
            bootstrap_secret: [7; 32],
            bootstrap_endpoint_id: [8; 32],
            bootstrap_addr: "127.0.0.1:41000".parse().unwrap(),
            workspace_id: [1; 32],
            invite_fact_id: [2; 32],
            user_authority_fact_id: None,
            endpoint_role: EndpointRole::Device,
            identity_scope: true,
        })
        .expect("accept");

        assert_eq!(output.facts.len(), 1);
        assert_eq!(output.receipt.invite_accepted_fact_id, output.facts[0].id);
        let accepted =
            super::super::decode_fact_payload(output.facts[0].body()).expect("decode accepted");
        assert_eq!(accepted.workspace_id, [1; 32]);
        assert_eq!(accepted.invite_fact_id, [2; 32]);
        assert_eq!(accepted.bootstrap_secret, [7; 32]);
        assert_eq!(accepted.bootstrap_endpoint_id, [8; 32]);
    }
}
