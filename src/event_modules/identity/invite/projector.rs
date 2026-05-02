use crate::store::TableRow;

use super::codec;
use super::tables;

pub fn project(bytes: &[u8]) -> Result<Vec<TableRow>, String> {
    let event = codec::decode(bytes)?;
    Ok(invite_secret(event.bootstrap_hash, event.bootstrap_secret))
}

pub fn invite_secret(bootstrap_hash: [u8; 32], private_key: [u8; 32]) -> Vec<TableRow> {
    vec![TableRow {
        table: tables::INVITE_SECRETS,
        key: bootstrap_hash.to_vec(),
        value: private_key.to_vec(),
    }]
}
