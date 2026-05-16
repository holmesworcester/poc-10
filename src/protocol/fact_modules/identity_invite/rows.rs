//! Projection row layouts for invite-secret state.
//!
//! Rows are keyed by `bootstrap_hash`. A connection bootstrap proves knowledge
//! of the bootstrap secret by presenting the matching hash; this projector
//! stores the private value beside the hash so the bootstrap path can look it
//! up locally without exposing the private value in the event.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::fact::InviteSecretFact;
use super::layout;

pub const INVITE_SECRET_ROWS: TableName = TableName::new("invite_secret_rows");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteSecretRow {
    pub bootstrap_hash: [u8; 32],
    pub bootstrap_secret: [u8; 32],
    pub workspace_id: Option<FactId>,
    pub invite_event_id: Option<FactId>,
}

pub fn invite_secret_key(bootstrap_hash: &[u8; 32]) -> Vec<u8> {
    bootstrap_hash.to_vec()
}

pub fn invite_secret_row(fact: &InviteSecretFact) -> Result<TableRow, String> {
    Ok(TableRow {
        table: INVITE_SECRET_ROWS,
        key: invite_secret_key(&fact.bootstrap_hash),
        value: layout::encode_row_value(fact)?,
    })
}

pub fn decode_invite_secret_row(key: &[u8], value: &[u8]) -> Result<InviteSecretRow, String> {
    if key.len() != 32 {
        return Err("invite_secret row key must be bootstrap_hash".to_string());
    }
    let mut bootstrap_hash = [0; 32];
    bootstrap_hash.copy_from_slice(key);
    let decoded = layout::decode_row_value(value)?;
    Ok(InviteSecretRow {
        bootstrap_hash,
        bootstrap_secret: decoded.bootstrap_secret,
        workspace_id: decoded.workspace_id,
        invite_event_id: decoded.invite_event_id,
    })
}
