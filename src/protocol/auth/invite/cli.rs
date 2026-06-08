//! CLI adapter for invite commands.
//!
//! This file owns argv parsing and text formatting only. Fact construction
//! lives in `commands.rs`; runtime admission and handler dispatch stay in the
//! protocol command handler/core app boundary.

use std::net::SocketAddr;

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::command_context::{CommandContext, CommandOutput};

use super::commands;

pub const INVITE_USAGE: &str = "invite [--workspace WORKSPACE_ID_HEX] --public-addr ADDR";
pub const INVITE_SERVER_USAGE: &str = "invite-server WORKSPACE_ID_HEX --public-addr ADDR";
pub const ACCEPT_USAGE: &str = "accept INVITE_LINK [--username USER] [--devicename DEVICE]";
pub const ACCEPT_INVITE_SERVER_USAGE: &str =
    "accept-invite-server INVITE_LINK [--devicename DEVICE]";
pub const LINK_USAGE: &str = "link WORKSPACE_ID_HEX --public-addr ADDR";
pub const ACCEPT_LINK_USAGE: &str = "accept-link INVITE_LINK --devicename DEVICE";

pub fn invite(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<commands::CreateInviteReceipt>, String> {
    let parsed = InviteArgs::parse(args)?;
    commands::create(
        ctx,
        commands::CreateInvite {
            created_at_ms: ctx.next_timestamp(),
            workspace_id: parsed.workspace_id,
            public_addr: parsed.public_addr,
        },
    )
}

pub fn accept(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
    from_listen_addr: Option<SocketAddr>,
) -> Result<CommandOutput<commands::AcceptInviteReceipt>, String> {
    let parsed = AcceptArgs::parse(args)?;
    commands::accept(
        ctx,
        commands::AcceptInvite {
            created_at_ms: ctx.next_timestamp(),
            invite: parsed.invite,
            username: parsed.username,
            device_name: parsed.device_name,
            from_listen_addr,
        },
    )
}

pub fn invite_server(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<commands::CreateInviteReceipt>, String> {
    let parsed = InviteServerArgs::parse(args)?;
    commands::create_invite_server(
        ctx,
        commands::CreateInviteServer {
            created_at_ms: ctx.next_timestamp(),
            workspace_id: parsed.workspace_id,
            public_addr: parsed.public_addr,
        },
    )
}

pub fn accept_invite_server(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
    from_listen_addr: Option<SocketAddr>,
) -> Result<CommandOutput<commands::AcceptInviteReceipt>, String> {
    let parsed = AcceptInviteServerArgs::parse(args)?;
    commands::accept_invite_server(
        ctx,
        commands::AcceptInviteServer {
            created_at_ms: ctx.next_timestamp(),
            invite: parsed.invite,
            device_name: parsed.device_name,
            from_listen_addr,
        },
    )
}

pub fn link(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<commands::CreateInviteReceipt>, String> {
    let parsed = LinkArgs::parse(args)?;
    commands::create_device_link(
        ctx,
        commands::CreateDeviceLink {
            created_at_ms: ctx.next_timestamp(),
            workspace_id: parsed.workspace_id,
            public_addr: parsed.public_addr,
        },
    )
}

pub fn accept_link(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
    from_listen_addr: Option<SocketAddr>,
) -> Result<CommandOutput<commands::AcceptInviteReceipt>, String> {
    let parsed = AcceptLinkArgs::parse(args)?;
    commands::accept_device_link(
        ctx,
        commands::AcceptDeviceLink {
            created_at_ms: ctx.next_timestamp(),
            invite: parsed.invite,
            device_name: parsed.device_name,
            from_listen_addr,
        },
    )
}

pub fn invite_output(receipt: &commands::CreateInviteReceipt) -> CliOutput {
    CliOutput::line(receipt.link.clone())
}

pub fn accept_output(receipt: &commands::AcceptInviteReceipt) -> CliOutput {
    let mut lines = vec![format!("connected: {}", receipt.connected_addr)];
    if let Some(workspace_id) = receipt.workspace_id {
        lines.push(format!(
            "workspace_id: {}",
            commands::encode_hex(&workspace_id)
        ));
    }
    if let Some(user_id) = receipt.user_id {
        lines.push(format!("user_id: {}", commands::encode_hex(&user_id)));
    }
    if let Some(endpoint_shared_id) = receipt.endpoint_shared_id {
        lines.push(format!(
            "endpoint_shared_id: {}",
            commands::encode_hex(&endpoint_shared_id)
        ));
    }
    if let Some(endpoint_role) = receipt.endpoint_role {
        lines.push(format!("endpoint_role: {}", endpoint_role.as_str()));
    }
    CliOutput::lines(lines)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InviteArgs {
    workspace_id: Option<[u8; 32]>,
    public_addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InviteServerArgs {
    workspace_id: [u8; 32],
    public_addr: SocketAddr,
}

impl InviteArgs {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let mut workspace_id = None;
        let mut public_addr = None;
        let mut rest = args.values().iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--workspace" => {
                    let value = rest
                        .next()
                        .ok_or_else(|| "invite --workspace requires a value".to_string())?;
                    workspace_id = Some(commands::decode_hex_32(value)?);
                }
                "--public-addr" => {
                    let value = rest
                        .next()
                        .ok_or_else(|| "invite --public-addr requires ADDR".to_string())?;
                    public_addr = Some(
                        value
                            .parse::<SocketAddr>()
                            .map_err(|_| "invite --public-addr is invalid".to_string())?,
                    );
                }
                other => return Err(format!("unknown invite argument `{other}`")),
            }
        }
        Ok(Self {
            workspace_id,
            public_addr: public_addr.ok_or_else(|| INVITE_USAGE.to_string())?,
        })
    }
}

impl InviteServerArgs {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let workspace = args.get(0).ok_or_else(|| INVITE_SERVER_USAGE.to_string())?;
        let workspace_id = commands::decode_hex_32(workspace)?;
        let mut public_addr = None;
        let mut rest = args.values()[1..].iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--public-addr" => {
                    let value = rest
                        .next()
                        .ok_or_else(|| "invite-server --public-addr requires ADDR".to_string())?;
                    public_addr = Some(
                        value
                            .parse::<SocketAddr>()
                            .map_err(|_| "invite-server --public-addr is invalid".to_string())?,
                    );
                }
                other => return Err(format!("unknown invite-server argument `{other}`")),
            }
        }
        Ok(Self {
            workspace_id,
            public_addr: public_addr.ok_or_else(|| INVITE_SERVER_USAGE.to_string())?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptArgs {
    invite: commands::Invite,
    username: Option<String>,
    device_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinkArgs {
    workspace_id: [u8; 32],
    public_addr: SocketAddr,
}

impl LinkArgs {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let workspace = args.get(0).ok_or_else(|| LINK_USAGE.to_string())?;
        let workspace_id = commands::decode_hex_32(workspace)?;
        let mut public_addr = None;
        let mut rest = args.values()[1..].iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--public-addr" => {
                    let value = rest
                        .next()
                        .ok_or_else(|| "link --public-addr requires ADDR".to_string())?;
                    public_addr = Some(
                        value
                            .parse::<SocketAddr>()
                            .map_err(|_| "link --public-addr is invalid".to_string())?,
                    );
                }
                other => return Err(format!("unknown link argument `{other}`")),
            }
        }
        Ok(Self {
            workspace_id,
            public_addr: public_addr.ok_or_else(|| LINK_USAGE.to_string())?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptLinkArgs {
    invite: commands::Invite,
    device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptInviteServerArgs {
    invite: commands::Invite,
    device_name: String,
}

impl AcceptLinkArgs {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let invite_link = args.get(0).ok_or_else(|| ACCEPT_LINK_USAGE.to_string())?;
        let invite = commands::parse(invite_link)?;
        let mut device_name = None;
        let mut rest = args.values()[1..].iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--devicename" | "--device-name" => {
                    device_name = Some(
                        rest.next()
                            .ok_or_else(|| "accept-link --devicename requires a value".to_string())?
                            .to_string(),
                    );
                }
                other => return Err(format!("unknown accept-link argument `{other}`")),
            }
        }
        Ok(Self {
            invite,
            device_name: device_name.ok_or_else(|| ACCEPT_LINK_USAGE.to_string())?,
        })
    }
}

impl AcceptInviteServerArgs {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let invite_link = args
            .get(0)
            .ok_or_else(|| ACCEPT_INVITE_SERVER_USAGE.to_string())?;
        let invite = commands::parse(invite_link)?;
        let mut device_name = Some("invite-server".to_string());
        let mut rest = args.values()[1..].iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--devicename" | "--device-name" => {
                    device_name = Some(
                        rest.next()
                            .ok_or_else(|| {
                                "accept-invite-server --devicename requires a value".to_string()
                            })?
                            .to_string(),
                    );
                }
                other => return Err(format!("unknown accept-invite-server argument `{other}`")),
            }
        }
        Ok(Self {
            invite,
            device_name: device_name.ok_or_else(|| ACCEPT_INVITE_SERVER_USAGE.to_string())?,
        })
    }
}

impl AcceptArgs {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let invite_link = args.get(0).ok_or_else(|| ACCEPT_USAGE.to_string())?;
        let invite = commands::parse(invite_link)?;
        let mut username = None;
        let mut device_name = None;
        let mut rest = args.values()[1..].iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--username" => {
                    username = Some(
                        rest.next()
                            .ok_or_else(|| "accept --username requires a value".to_string())?
                            .to_string(),
                    );
                }
                "--devicename" | "--device-name" => {
                    device_name = Some(
                        rest.next()
                            .ok_or_else(|| "accept --devicename requires a value".to_string())?
                            .to_string(),
                    );
                }
                other => return Err(format!("unknown accept argument `{other}`")),
            }
        }
        Ok(Self {
            invite,
            username,
            device_name,
        })
    }
}
