use std::{net::SocketAddr, str::FromStr};

use rand_core::{OsRng, RngCore};

use crate::store::Store;

use super::super::endpoint;
use super::types::Invite;
use super::{projector, tables};

const INVITE_PREFIX: &str = "topo://invite/";
const INVITE_VERSION: &str = "v6";
const INVITE_KIND: &str = "user";
const LABEL_INVITE_ID: &str = "INVITE_ID";
const LABEL_INVITE_PRIVKEY: &str = "INVITE_PRIVKEY";
const LABEL_WORKSPACE: &str = "WORKSPACE";
const LABEL_ENDPOINT_ID: &str = "ENDPOINT_ID";
const LABEL_ADDRESS: &str = "ADDRESS";

pub fn create(store: &Store, public_addr: SocketAddr) -> Result<String, String> {
    let local = endpoint::commands::ensure_local_keypair(store)?;
    let invite_event_id = nonce32();
    let bootstrap_secret = nonce32();
    let workspace_id = nonce32();
    store
        .insert_table_rows(projector::invite_secret(
            secret_hash(&bootstrap_secret),
            bootstrap_secret,
        ))
        .map_err(|err| format!("store invite secret: {err}"))?;
    Ok(format!(
        "{INVITE_PREFIX}{INVITE_VERSION}/{INVITE_KIND}/{LABEL_INVITE_ID}.{invite_id}/{LABEL_INVITE_PRIVKEY}.{invite_secret}/{LABEL_WORKSPACE}.{workspace}/{LABEL_ENDPOINT_ID}.{endpoint}/{LABEL_ADDRESS}.{address}",
        invite_id = encode_hex(&invite_event_id),
        invite_secret = encode_hex(&bootstrap_secret),
        workspace = encode_hex(&workspace_id),
        endpoint = encode_hex(&local.endpoint),
        address = encode_address(public_addr),
    ))
}

pub fn addr(invite: &str) -> Result<SocketAddr, String> {
    Ok(parse(invite)?.addr)
}

pub fn parse(value: &str) -> Result<Invite, String> {
    let body = value
        .strip_prefix(INVITE_PREFIX)
        .ok_or_else(|| "invite must start with topo://invite/".to_string())?;
    let mut parts = body.split('/');
    let version = parts
        .next()
        .ok_or_else(|| "invite is missing version".to_string())?;
    if version != INVITE_VERSION {
        return Err(format!("unsupported invite version {version}"));
    }
    let kind = parts
        .next()
        .ok_or_else(|| "invite is missing kind".to_string())?;
    if kind != INVITE_KIND {
        return Err(format!("unsupported invite kind {kind}"));
    }

    let mut endpoint = None;
    let mut bootstrap_secret = None;
    let mut addr = None;
    let mut invite_event_id = None;
    let mut workspace_id = None;

    for part in parts {
        let (label, value) = part
            .split_once('.')
            .ok_or_else(|| format!("invite part `{part}` is missing label"))?;
        match label {
            LABEL_INVITE_ID => invite_event_id = Some(decode_hex_32(value)?),
            LABEL_INVITE_PRIVKEY => bootstrap_secret = Some(decode_hex_32(value)?),
            LABEL_WORKSPACE => workspace_id = Some(decode_hex_32(value)?),
            LABEL_ENDPOINT_ID => endpoint = Some(decode_hex_32(value)?),
            LABEL_ADDRESS => addr = Some(decode_address(value)?),
            other => return Err(format!("unknown invite part `{other}`")),
        }
    }

    Ok(Invite {
        endpoint: endpoint.ok_or_else(|| "invite is missing ENDPOINT_ID".to_string())?,
        bootstrap_secret: bootstrap_secret
            .ok_or_else(|| "invite is missing INVITE_PRIVKEY".to_string())?,
        addr: addr.ok_or_else(|| "invite is missing ADDRESS".to_string())?,
        invite_event_id: invite_event_id
            .ok_or_else(|| "invite is missing INVITE_ID".to_string())?,
        workspace_id: workspace_id.ok_or_else(|| "invite is missing WORKSPACE".to_string())?,
    })
}

pub fn secret_hash(secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo-bootstrap-token-v1");
    hasher.update(encode_hex(secret).as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn bootstrap_hash_is_authorized(
    store: &Store,
    bootstrap_hash: &[u8; 32],
) -> Result<bool, String> {
    store
        .table_row(tables::INVITE_SECRETS, bootstrap_hash)
        .map(|row| row.is_some())
        .map_err(|err| format!("load invite secret: {err}"))
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

fn encode_address(addr: SocketAddr) -> String {
    format!("{}_{}", addr.ip(), addr.port())
}

fn decode_address(value: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = SocketAddr::from_str(value) {
        return Ok(addr);
    }
    let (host, port) = value
        .rsplit_once('_')
        .ok_or_else(|| "invite ADDRESS must include a port".to_string())?;
    let port = port
        .parse::<u16>()
        .map_err(|_| "invite ADDRESS port is invalid".to_string())?;
    let candidate = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    SocketAddr::from_str(&candidate).map_err(|_| "invite ADDRESS is invalid".to_string())
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("invite hex field must be 64 hex characters".to_string());
    }
    let mut out = [0; 32];
    let bytes = value.as_bytes();
    for idx in 0..32 {
        out[idx] = (hex_value(bytes[idx * 2])? << 4) | hex_value(bytes[idx * 2 + 1])?;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invite hex field is not hex".to_string()),
    }
}

fn nonce32() -> [u8; 32] {
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}
