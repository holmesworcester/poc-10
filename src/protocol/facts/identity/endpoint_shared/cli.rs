//! CLI formatting for local identity and workspace peers.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::command_context::CommandContext;
use crate::protocol::facts::identity;

use super::fact::EndpointRole;
use super::queries;

pub const IDENTITY_USAGE: &str = "identity";
pub const PEERS_USAGE: &str = "peers WORKSPACE_ID_HEX";

pub fn identity(ctx: &CommandContext<'_>, _args: CliArgs<'_>) -> Result<CliOutput, String> {
    let endpoint = identity::endpoint::queries::local_endpoint_public(ctx.store())?
        .ok_or_else(|| "local endpoint has not been created".to_string())?;
    let mut lines = vec![
        format!("endpoint_id: {}", encode_hex(&endpoint.endpoint)),
        format!(
            "signing_public_key: {}",
            encode_hex(&endpoint.signing_public_key)
        ),
    ];
    for membership in identity::workspace::local_membership::local_memberships(ctx.store())? {
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
    let workspace_id = decode_hex_32(workspace)?;
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

pub fn encode_hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("workspace id must be 64 hex characters".to_string());
    }
    let mut out = [0u8; 32];
    let bytes = value.as_bytes();
    for index in 0..32 {
        let hi = hex_nibble(bytes[index * 2])?;
        let lo = hex_nibble(bytes[index * 2 + 1])?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("hex value contains non-hex character".to_string()),
    }
}
