//! Product runtime count read model for the `count` CLI command.
//!
//! This is intentionally separate from workspace row queries. It composes
//! protocol runtime state across facts, the context change pipeline, connections, and
//! accepted invites for one user-facing diagnostic report.

use crate::protocol::facts::connection;
use crate::protocol::facts::identity;
use crate::protocol::facts::sync::shared_fact;
use crate::protocol::runtime::ProtocolRuntime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeCountReport {
    pub workspace_rows: usize,
    pub facts: usize,
    pub sync_facts: usize,
    pub applied_facts: usize,
    pub connections: usize,
    pub connection_facts: usize,
    pub invite_accepted: usize,
}

pub fn runtime_count_report(runtime: &ProtocolRuntime) -> Result<RuntimeCountReport, String> {
    let workspace_rows = runtime
        .store()
        .table_row_count(super::rows::WORKSPACE_ROWS)
        .map_err(|err| format!("count workspace rows: {err}"))?;
    let facts = runtime.facts().count();
    let sync_facts = shared_fact::sync_status(runtime.store())?.indexed_facts;
    let applied_facts = facts.saturating_sub(runtime.pending_fact_count());
    let connections = runtime
        .store()
        .table_rows(connection::response::rows::CONNECTION_RESPONSE_ROWS)
        .map_err(|err| format!("count connections: {err}"))?
        .len();
    let connection_requests = runtime
        .store()
        .table_rows(connection::request::rows::CONNECTION_REQUEST_ROWS)
        .map_err(|err| format!("count connection requests: {err}"))?
        .len();
    let invite_accepted = runtime
        .store()
        .table_rows(identity::invite_accepted::rows::INVITE_ACCEPTED_ROWS)
        .map_err(|err| format!("count invite accepted: {err}"))?
        .len();
    Ok(RuntimeCountReport {
        workspace_rows,
        facts,
        sync_facts,
        applied_facts,
        connections,
        connection_facts: connection_requests + connections,
        invite_accepted,
    })
}
