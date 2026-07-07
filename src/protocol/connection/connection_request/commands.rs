//! User-facing constructor for membership connection requests.
//!
//! `connect` to a known endpoint gathers the local handshake snapshot from the
//! runtime — the local endpoint identity and the membership connection plan — and
//! calls `author` to build the local facts that start a membership handshake.
//! There is no invite material; the request carries the initiator's
//! `endpoint_shared` membership id as its authorization witness.
//!
//! Commands read the runtime and build the authoring snapshot; `author` does the
//! pure construction and self-check, and projection decides when the request is
//! admissible and emits the network send.

use std::net::SocketAddr;

use crate::core::cli::encode_hex;
use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::facts::FactId;
use crate::protocol::auth::endpoint::create::local_endpoint;

use super::author::{create, CreateConnectionRequest, CreateConnectionRequestReceipt};
use super::queries::choose_connection_mode;

pub const CONNECT_USAGE: &str = "connect ENDPOINT_ID_HEX";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connect {
    pub created_at_ms: u64,
    pub target_endpoint: FactId,
    pub from_listen_addr: Option<SocketAddr>,
}

/// Build a membership connection request to a known endpoint, using the
/// connection-mode trigger. Errors if no membership connection is available
/// (the endpoint is unknown or has not synced our membership yet) — the caller
/// should accept an invite to bootstrap first.
pub fn connect(
    ctx: &CommandContext<'_>,
    input: Connect,
) -> Result<CommandOutput<CreateConnectionRequestReceipt>, String> {
    if input.from_listen_addr.is_none() {
        return Err("connect requires a running local daemon".to_string());
    }
    let local = local_endpoint(ctx.store())?
        .ok_or_else(|| "connect requires a local endpoint identity".to_string())?;
    let plan = choose_connection_mode(ctx.store(), input.target_endpoint)?.ok_or_else(|| {
        format!(
            "no membership connection available for {}; accept an invite to bootstrap first",
            encode_hex(&input.target_endpoint)
        )
    })?;
    create(CreateConnectionRequest {
        created_at_ms: input.created_at_ms,
        local_endpoint: local,
        remote_endpoint: plan.to_endpoint,
        initiator_endpoint_shared_id: plan.initiator_endpoint_shared_id,
        from_listen_addr: input.from_listen_addr,
        to_listen_addr: Some(plan.addr),
    })
}
