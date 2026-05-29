//! Connection-maintenance candidate index and status view.
//!
//! The candidate index is opaque rows keyed by the local request id. Each row
//! carries everything `maintain_connections` needs to queue a bootstrap send
//! without reading auth-owned or endpoint-owned tables: the peer endpoint, the
//! initiator ephemeral secret id, and the bootstrap return address. Rows are
//! purely registration-derived — `maintain_connections` never mutates them — so
//! replay rebuilds the index deterministically by reprojecting retained request
//! facts and dispatching the replay-allowed registration intents.
//!
//! This module owns the row codec, the candidate read helpers, and the status
//! view that the `connection-maintenance-status` diagnostic prints. Intent
//! handlers emit row mutations through `candidate_row`/`candidate_key` and read
//! through `candidate_rows`; they do not declare the table shape themselves.

use crate::core::facts::FactId;
use crate::core::store::{Store, TableName, TableRow};
use std::net::SocketAddr;

use crate::protocol::connection::request::create as addr;
use crate::protocol::connection::response::rows::CONNECTION_RESPONSE_ROWS;

/// Connection-maintenance candidate index table.
pub const CONNECTION_CANDIDATE_ROWS: TableName = TableName::new("connection_candidate_rows");

const VALUE_BYTES: usize = 32 + 32 + addr::ADDR_BLOCK_BYTES;

/// One connection-maintenance candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateRow {
    /// Local request fact id; also the candidate row key.
    pub request_id: FactId,
    /// Peer endpoint this candidate bootstraps to.
    pub to_endpoint: FactId,
    /// Initiator ephemeral secret used to seal the bootstrap request.
    pub initiator_ephemeral_secret_id: FactId,
    /// Bootstrap return address for the peer.
    pub addr: SocketAddr,
}

pub fn candidate_key(request_id: &FactId) -> Vec<u8> {
    request_id.to_vec()
}

pub fn candidate_row(candidate: &CandidateRow) -> Result<TableRow, String> {
    let mut value = Vec::with_capacity(VALUE_BYTES);
    value.extend_from_slice(&candidate.to_endpoint);
    value.extend_from_slice(&candidate.initiator_ephemeral_secret_id);
    value.extend_from_slice(&addr::encode_optional_addr(Some(candidate.addr))?);
    Ok(TableRow {
        table: CONNECTION_CANDIDATE_ROWS,
        key: candidate_key(&candidate.request_id),
        value,
    })
}

pub fn decode_candidate_row(key: &[u8], value: &[u8]) -> Result<CandidateRow, String> {
    let request_id: FactId = key
        .try_into()
        .map_err(|_| "connection candidate key is not a 32-byte request id".to_string())?;
    if value.len() != VALUE_BYTES {
        return Err("connection candidate row has wrong length".to_string());
    }
    let to_endpoint: FactId = value[0..32].try_into().unwrap();
    let initiator_ephemeral_secret_id: FactId = value[32..64].try_into().unwrap();
    let mut addr_bytes = [0u8; addr::ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&value[64..]);
    let addr = addr::decode_optional_addr(&addr_bytes)?
        .ok_or_else(|| "connection candidate row addr is missing".to_string())?;
    Ok(CandidateRow {
        request_id,
        to_endpoint,
        initiator_ephemeral_secret_id,
        addr,
    })
}

/// Read all registered candidates, ordered by request id.
pub fn candidate_rows(store: &Store) -> Result<Vec<CandidateRow>, String> {
    let mut candidates = store
        .table_rows(CONNECTION_CANDIDATE_ROWS)
        .map_err(|err| format!("read connection candidates: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_candidate_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    candidates.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    Ok(candidates)
}

/// Connection-maintenance-owned view for the status diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceStatus {
    /// Pending bootstrap candidates, ordered by request id.
    pub candidates: Vec<CandidateRow>,
    /// Established connections (materialized connection responses).
    pub active_connections: usize,
}

/// Read connection-maintenance-owned state for the status diagnostic.
///
/// Reads only connection-owned tables: the candidate index and the established
/// connection response rows. It never reads auth-owned endpoint tables.
pub fn connection_maintenance_status(store: &Store) -> Result<MaintenanceStatus, String> {
    let candidates = candidate_rows(store)?;
    let active_connections = store
        .table_row_count(CONNECTION_RESPONSE_ROWS)
        .map_err(|err| format!("count active connections: {err}"))?;
    Ok(MaintenanceStatus {
        candidates,
        active_connections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CandidateRow {
        CandidateRow {
            request_id: [1; 32],
            to_endpoint: [2; 32],
            initiator_ephemeral_secret_id: [3; 32],
            addr: "127.0.0.1:41001".parse().unwrap(),
        }
    }

    #[test]
    fn candidate_row_roundtrips() {
        let row = candidate_row(&sample()).expect("encode");
        let decoded = decode_candidate_row(&row.key, &row.value).expect("decode");
        assert_eq!(decoded, sample());
    }
}
