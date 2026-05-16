//! Product runtime count read model for the `count` CLI command.
//!
//! This is intentionally separate from workspace row queries. It composes
//! protocol runtime state across facts, the wake loop, connections, and
//! accepted invites for one user-facing diagnostic report.

use crate::event_modules::{connection_request, connection_response, identity_invite_accepted};
use crate::protocol::runtime::{is_sync_seed_fact, ProtocolRuntime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeCountReport {
    pub workspace_rows: usize,
    pub events: usize,
    pub sync_events: usize,
    pub applied_events: usize,
    pub connections: usize,
    pub connection_events: usize,
    pub invite_accepted: usize,
}

pub fn runtime_count_report(runtime: &ProtocolRuntime) -> Result<RuntimeCountReport, String> {
    let workspace_rows = runtime
        .store()
        .table_row_count(super::rows::WORKSPACE_ROWS)
        .map_err(|err| format!("count workspace rows: {err}"))?;
    let events = runtime.facts().count();
    let sync_events = runtime
        .facts()
        .filter(|fact| is_sync_seed_fact(fact))
        .count();
    let applied_events = events.saturating_sub(runtime.wake_loop().pending_len());
    let connections = runtime
        .store()
        .table_rows(connection_response::rows::CONNECTION_RESPONSE_ROWS)
        .map_err(|err| format!("count connections: {err}"))?
        .len();
    let connection_requests = runtime
        .store()
        .table_rows(connection_request::rows::CONNECTION_REQUEST_ROWS)
        .map_err(|err| format!("count connection requests: {err}"))?
        .len();
    let invite_accepted = runtime
        .store()
        .table_rows(identity_invite_accepted::rows::INVITE_ACCEPTED_ROWS)
        .map_err(|err| format!("count invite accepted: {err}"))?
        .len();
    Ok(RuntimeCountReport {
        workspace_rows,
        events,
        sync_events,
        applied_events,
        connections,
        connection_events: connection_requests + connections,
        invite_accepted,
    })
}
