//! Projector for invite-secret events.
//!
//! Projection makes a bootstrap hash authorized by storing the corresponding
//! private value locally. The row is intentionally keyed by hash so a connection
//! request can prove knowledge without exposing the private value in the event.

use crate::core::store::TableRow;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::codec;
use super::schema;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let event = codec::decode(bytes)?;
    Ok(ProjectionOutput::rows(invite_secret(
        event.bootstrap_hash,
        event.bootstrap_secret,
    )))
}

pub fn invite_secret(bootstrap_hash: [u8; 32], private_key: [u8; 32]) -> Vec<TableRow> {
    vec![TableRow {
        table: schema::INVITE_SECRETS,
        key: bootstrap_hash.to_vec(),
        value: private_key.to_vec(),
    }]
}
