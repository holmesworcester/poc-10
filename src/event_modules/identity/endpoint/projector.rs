use crate::store::ModuleRow;

use super::tables;
use super::types::EndpointId;

pub fn local_endpoint(endpoint: EndpointId, secret: [u8; 32]) -> Vec<ModuleRow> {
    vec![
        ModuleRow {
            table: tables::LOCAL_ENDPOINT,
            key: b"local".to_vec(),
            value: endpoint.to_vec(),
        },
        ModuleRow {
            table: tables::LOCAL_ENDPOINT_SECRET,
            key: b"local".to_vec(),
            value: secret.to_vec(),
        },
    ]
}
