//! CLI adapter for invite commands.
//!
//! This file owns argv parsing and text formatting only. Fact construction
//! lives in `api.rs`; runtime admission and handler dispatch stay in the
//! protocol command handler/core app boundary.

use std::net::SocketAddr;

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::command::{AuthoredFacts, CommandClock};
use crate::core::db::Db;

use super::api;

pub const INVITE_USAGE: &str = "invite [--workspace WORKSPACE_ID_HEX] [--public-addr ADDR]";
pub const INVITE_SERVER_USAGE: &str = "invite-server WORKSPACE_ID_HEX --public-addr ADDR";
pub const ACCEPT_USAGE: &str = "accept INVITE_LINK [--username USER] [--devicename DEVICE]";
pub const ACCEPT_INVITE_SERVER_USAGE: &str =
    "accept-invite-server INVITE_LINK [--devicename DEVICE]";
pub const LINK_USAGE: &str = "link WORKSPACE_ID_HEX --public-addr ADDR";
pub const ACCEPT_LINK_USAGE: &str = "accept-link INVITE_LINK --devicename DEVICE";

pub fn invite(
    store: &Db,
    clock: &dyn CommandClock,
    args: CliArgs<'_>,
    from_listen_addr: Option<SocketAddr>,
) -> Result<AuthoredFacts<api::CreateInviteReceipt>, String> {
    let parsed = InviteArgs::parse(args)?;
    // Only auto-fill from the daemon listen address when it is a concrete,
    // dialable address. A wildcard bind (`0.0.0.0` / `[::]`) is a valid listen
    // address but cannot be dialed by a peer, so copying it into the invite link
    // would silently produce an unusable invite; require an explicit
    // `--public-addr` in that case.
    let dialable_listen_addr = from_listen_addr.filter(|addr| !addr.ip().is_unspecified());
    let public_addr = parsed
        .public_addr
        .or(dialable_listen_addr)
        .ok_or_else(|| {
            let hint = match from_listen_addr {
                Some(addr) if addr.ip().is_unspecified() => format!(
                    "daemon listens on wildcard {addr}, which peers cannot dial — pass --public-addr ADDR"
                ),
                _ => "no daemon listen address found — start the daemon or pass --public-addr".to_string(),
            };
            format!("{INVITE_USAGE}; {hint}")
        })?;
    api::create(
        store,
        api::CreateInvite {
            created_at_ms: clock.next_timestamp(),
            workspace_id: parsed.workspace_id,
            public_addr,
        },
    )
}

pub fn accept(
    store: &Db,
    clock: &dyn CommandClock,
    args: CliArgs<'_>,
    from_listen_addr: Option<SocketAddr>,
) -> Result<AuthoredFacts<api::AcceptInviteReceipt>, String> {
    let parsed = AcceptArgs::parse(args)?;
    api::accept(
        store,
        api::AcceptInvite {
            created_at_ms: clock.next_timestamp(),
            invite: parsed.invite,
            username: parsed.username,
            device_name: parsed.device_name,
            from_listen_addr,
        },
    )
}

pub fn invite_server(
    store: &Db,
    clock: &dyn CommandClock,
    args: CliArgs<'_>,
) -> Result<AuthoredFacts<api::CreateInviteReceipt>, String> {
    let parsed = InviteServerArgs::parse(args)?;
    api::create_invite_server(
        store,
        api::CreateInviteServer {
            created_at_ms: clock.next_timestamp(),
            workspace_id: parsed.workspace_id,
            public_addr: parsed.public_addr,
        },
    )
}

pub fn accept_invite_server(
    store: &Db,
    clock: &dyn CommandClock,
    args: CliArgs<'_>,
    from_listen_addr: Option<SocketAddr>,
) -> Result<AuthoredFacts<api::AcceptInviteReceipt>, String> {
    let parsed = AcceptInviteServerArgs::parse(args)?;
    api::accept_invite_server(
        store,
        api::AcceptInviteServer {
            created_at_ms: clock.next_timestamp(),
            invite: parsed.invite,
            device_name: parsed.device_name,
            from_listen_addr,
        },
    )
}

pub fn link(
    store: &Db,
    clock: &dyn CommandClock,
    args: CliArgs<'_>,
) -> Result<AuthoredFacts<api::CreateInviteReceipt>, String> {
    let parsed = LinkArgs::parse(args)?;
    api::create_device_link(
        store,
        api::CreateDeviceLink {
            created_at_ms: clock.next_timestamp(),
            workspace_id: parsed.workspace_id,
            public_addr: parsed.public_addr,
        },
    )
}

pub fn accept_link(
    store: &Db,
    clock: &dyn CommandClock,
    args: CliArgs<'_>,
    from_listen_addr: Option<SocketAddr>,
) -> Result<AuthoredFacts<api::AcceptInviteReceipt>, String> {
    let parsed = AcceptLinkArgs::parse(args)?;
    api::accept_device_link(
        store,
        api::AcceptDeviceLink {
            created_at_ms: clock.next_timestamp(),
            invite: parsed.invite,
            device_name: parsed.device_name,
            from_listen_addr,
        },
    )
}

pub fn invite_output(receipt: &api::CreateInviteReceipt) -> CliOutput {
    CliOutput::line(receipt.link.clone())
}

/// `invite_output` plus a copy-paste-ready accept line. Used by the workspace
/// `invite` command (not `link`/`invite-server`, which accept differently).
pub fn invite_output_with_next_step(receipt: &api::CreateInviteReceipt) -> CliOutput {
    CliOutput::lines(vec![
        receipt.link.clone(),
        format!(
            "next: con --db PEER.db accept {} --username NAME --devicename DEVICE",
            receipt.link
        ),
    ])
}

pub fn accept_output(receipt: &api::AcceptInviteReceipt) -> CliOutput {
    let mut lines = vec![format!("connected: {}", receipt.connected_addr)];
    if let Some(workspace_id) = receipt.workspace_id {
        lines.push(format!("workspace_id: {}", api::encode_hex(&workspace_id)));
    }
    if let Some(user_id) = receipt.user_id {
        lines.push(format!("user_id: {}", api::encode_hex(&user_id)));
    }
    if let Some(endpoint_shared_id) = receipt.endpoint_shared_id {
        lines.push(format!(
            "endpoint_shared_id: {}",
            api::encode_hex(&endpoint_shared_id)
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
    public_addr: Option<SocketAddr>,
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
                    workspace_id = Some(api::decode_hex_32(value)?);
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
            public_addr,
        })
    }
}

impl InviteServerArgs {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let workspace = args.get(0).ok_or_else(|| INVITE_SERVER_USAGE.to_string())?;
        let workspace_id = api::decode_hex_32(workspace)?;
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
    invite: api::Invite,
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
        let workspace_id = api::decode_hex_32(workspace)?;
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
    invite: api::Invite,
    device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptInviteServerArgs {
    invite: api::Invite,
    device_name: String,
}

impl AcceptLinkArgs {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let invite_link = args.get(0).ok_or_else(|| ACCEPT_LINK_USAGE.to_string())?;
        let invite = api::parse(invite_link)?;
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
        let invite = api::parse(invite_link)?;
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
        let invite = api::parse(invite_link)?;
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
