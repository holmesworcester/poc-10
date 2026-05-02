use crate::store::TableRow;

use super::tables;

pub fn invite_secret(bootstrap_hash: [u8; 32], private_key: [u8; 32]) -> Vec<TableRow> {
    vec![TableRow {
        table: tables::INVITE_SECRETS,
        key: bootstrap_hash.to_vec(),
        value: private_key.to_vec(),
    }]
}
