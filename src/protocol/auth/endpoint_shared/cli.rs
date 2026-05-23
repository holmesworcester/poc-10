//! CLI formatting for local identity and workspace peers.
//!
//! This file owns only argv parsing and text formatting for projected identity
//! reads. Runtime draining, handler dispatch, and persistence stay at the root
//! app/runtime boundary.

use crate::core::cli::{decode_hex_32_named, encode_hex, CliArgs, CliOutput};
use crate::core::command_context::CommandContext;
use crate::protocol::auth;

use super::fact::EndpointRole;
use super::queries;

pub const IDENTITY_USAGE: &str = "identity";
pub const PEERS_USAGE: &str = "peers WORKSPACE_ID_HEX";

pub fn identity(ctx: &CommandContext<'_>, _args: CliArgs<'_>) -> Result<CliOutput, String> {
    let endpoint = auth::endpoint::queries::local_endpoint_public(ctx.store())?
        .ok_or_else(|| "local endpoint has not been created".to_string())?;
    let mut lines = vec![
        format!("endpoint_id: {}", encode_hex(&endpoint.endpoint)),
        format!(
            "signing_public_key: {}",
            encode_hex(&endpoint.signing_public_key)
        ),
    ];
    for membership in auth::workspace::queries::local_memberships(ctx.store())? {
        lines.push(format!(
            "workspace: {} {} user_id={} endpoint_shared_id={} endpoint_role={}",
            encode_hex(&membership.workspace_id),
            membership.workspace_name,
            encode_hex(&membership.endpoint_shared.user_authority_fact_id),
            encode_hex(&membership.endpoint_shared.endpoint_shared_id),
            role_name(membership.endpoint_shared.endpoint_role)
        ));
    }
    Ok(CliOutput::lines(lines))
}

pub fn peers(ctx: &CommandContext<'_>, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let workspace = args.get(0).ok_or_else(|| PEERS_USAGE.to_string())?;
    let workspace_id = decode_hex_32_named(workspace, "workspace id")?;
    let lines = queries::peers_in_workspace(ctx.store(), workspace_id)?
        .into_iter()
        .map(|peer| {
            format!(
                "{} user_id={} endpoint_role={} device_name={}",
                encode_hex(&peer.endpoint_id),
                encode_hex(&peer.user_authority_fact_id),
                role_name(peer.endpoint_role),
                peer.device_name
            )
        })
        .collect::<Vec<_>>();
    Ok(CliOutput::lines(lines))
}

fn role_name(role: EndpointRole) -> &'static str {
    match role {
        EndpointRole::Device => "device",
        EndpointRole::InviteServer => "invite-server",
    }
}
