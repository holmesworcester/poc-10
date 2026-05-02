use crate::store::TableRow;

use super::codec;
use super::tables;
use super::types::EndpointId;

pub fn project(bytes: &[u8]) -> Result<Vec<TableRow>, String> {
    let event = codec::decode(bytes)?;
    Ok(local_endpoint(event.endpoint, event.secret))
}

pub fn local_endpoint(endpoint: EndpointId, secret: [u8; 32]) -> Vec<TableRow> {
    vec![
        TableRow {
            table: tables::LOCAL_ENDPOINT,
            key: b"local".to_vec(),
            value: endpoint.to_vec(),
        },
        TableRow {
            table: tables::LOCAL_ENDPOINT_SECRET,
            key: b"local".to_vec(),
            value: secret.to_vec(),
        },
    ]
}
