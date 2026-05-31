//! Durable rows for admitted connection requests.
//!
//! Rows are keyed by request fact id and store the endpoint pair plus the
//! invite, invite-secret, and initiator ephemeral-secret dependency ids. That
//! compact row lets response projection and diagnostics resolve request
//! dependencies without re-decoding the full fact body.
//!
//! Change this file for request row compatibility. Projection owns when the row
//! is written, and layout owns canonical request fact bytes.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::fact::{BootstrapRequestFact, EndpointId};

pub const BOOTSTRAP_REQUEST_ROWS: TableName = TableName::new("bootstrap_request_rows");
pub const ROW_VALUE_BYTES: usize = 32 + 32 + 32 + 32 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapRequestRow {
    pub request_id: FactId,
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub invite_fact_id: FactId,
    pub invite_secret_fact_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
}

pub fn bootstrap_request_key(request_id: &FactId) -> Vec<u8> {
    request_id.to_vec()
}

pub fn bootstrap_request_row(
    request_id: FactId,
    fact: &BootstrapRequestFact,
) -> Result<TableRow, String> {
    let mut value = vec![0; ROW_VALUE_BYTES];
    value[0..32].copy_from_slice(&fact.from_endpoint);
    value[32..64].copy_from_slice(&fact.to_endpoint);
    value[64..96].copy_from_slice(&fact.invite_fact_id);
    value[96..128].copy_from_slice(&fact.invite_secret_fact_id);
    value[128..160].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
    Ok(TableRow {
        table: BOOTSTRAP_REQUEST_ROWS,
        key: bootstrap_request_key(&request_id),
        value,
    })
}

pub fn decode_bootstrap_request_row(
    key: &[u8],
    value: &[u8],
) -> Result<BootstrapRequestRow, String> {
    if key.len() != 32 {
        return Err("connection request row key must be the request fact id".to_string());
    }
    if value.len() != ROW_VALUE_BYTES {
        return Err("connection request row value is malformed".to_string());
    }
    let mut request_id = [0; 32];
    request_id.copy_from_slice(key);
    let mut from_endpoint = [0; 32];
    from_endpoint.copy_from_slice(&value[0..32]);
    let mut to_endpoint = [0; 32];
    to_endpoint.copy_from_slice(&value[32..64]);
    let mut invite_fact_id = [0; 32];
    invite_fact_id.copy_from_slice(&value[64..96]);
    let mut invite_secret_fact_id = [0; 32];
    invite_secret_fact_id.copy_from_slice(&value[96..128]);
    let mut initiator_ephemeral_secret_fact_id = [0; 32];
    initiator_ephemeral_secret_fact_id.copy_from_slice(&value[128..160]);
    Ok(BootstrapRequestRow {
        request_id,
        from_endpoint,
        to_endpoint,
        invite_fact_id,
        invite_secret_fact_id,
        initiator_ephemeral_secret_fact_id,
    })
}
