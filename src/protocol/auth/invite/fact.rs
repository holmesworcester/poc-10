//! Invite-secret fact shape for the poc-10 target tree.
//!
//! The shareable invite link carries the bootstrap secret to the invited peer.
//! Locally we project the hash-to-secret mapping so bootstrap authorization is
//! a projected fact rather than hidden CLI state. The fact is local-only.
//!
//! `workspace_id` and `invite_fact_id` are jointly optional: a freshly minted
//! invite (creator side) does not yet know which shared `invite_server` fact
//! id it will be paired with, while an accepted invite (acceptor side) scopes
//! the secret to one workspace/invite pair.

use crate::core::facts::FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteSecretFact {
    pub bootstrap_hash: [u8; 32],
    pub bootstrap_secret: [u8; 32],
    pub workspace_id: Option<FactId>,
    pub invite_fact_id: Option<FactId>,
}

impl InviteSecretFact {
    pub fn new(bootstrap_secret: [u8; 32]) -> Self {
        Self {
            bootstrap_hash: bootstrap_secret_hash(&bootstrap_secret),
            bootstrap_secret,
            workspace_id: None,
            invite_fact_id: None,
        }
    }

    pub fn scoped(
        bootstrap_secret: [u8; 32],
        workspace_id: FactId,
        invite_fact_id: FactId,
    ) -> Self {
        Self {
            bootstrap_hash: bootstrap_secret_hash(&bootstrap_secret),
            bootstrap_secret,
            workspace_id: Some(workspace_id),
            invite_fact_id: Some(invite_fact_id),
        }
    }

    pub fn validate(self) -> Result<Self, String> {
        if self.bootstrap_hash != bootstrap_secret_hash(&self.bootstrap_secret) {
            return Err("invite secret hash does not match secret".to_string());
        }
        if self.workspace_id.is_some() != self.invite_fact_id.is_some() {
            return Err("invite secret scope is incomplete".to_string());
        }
        Ok(self)
    }
}

pub fn bootstrap_secret_hash(secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo-bootstrap-token-v1");
    hasher.update(encode_hex(secret).as_bytes());
    *hasher.finalize().as_bytes()
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
