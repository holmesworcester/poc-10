//! Conversion between optional `SocketAddr` listen hints and the fixed
//! 19-byte addr block used inside the connection-request fact bytes.
//!
//! The conversion lives outside `layout.rs` because layout files are
//! restricted to fixed-byte mechanics; `std::net` types belong here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::core::wire;

pub const ADDR_BLOCK_BYTES: usize = 19;
pub const ADDR_FAMILY_NONE: u8 = 0;
pub const ADDR_FAMILY_V4: u8 = 1;
pub const ADDR_FAMILY_V6: u8 = 2;

pub fn encode_optional_addr(addr: Option<SocketAddr>) -> Result<[u8; ADDR_BLOCK_BYTES], String> {
    let mut out = [0u8; ADDR_BLOCK_BYTES];
    match addr {
        None => {
            out[0] = ADDR_FAMILY_NONE;
        }
        Some(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                out[0] = ADDR_FAMILY_V4;
                out[1..5].copy_from_slice(&ip.octets());
                wire::put_u16be(addr.port(), &mut out[17..19]).map_err(wire_err)?;
            }
            IpAddr::V6(ip) => {
                out[0] = ADDR_FAMILY_V6;
                out[1..17].copy_from_slice(&ip.octets());
                wire::put_u16be(addr.port(), &mut out[17..19]).map_err(wire_err)?;
            }
        },
    }
    Ok(out)
}

pub fn decode_optional_addr(bytes: &[u8; ADDR_BLOCK_BYTES]) -> Result<Option<SocketAddr>, String> {
    let family = bytes[0];
    let raw = &bytes[1..17];
    let port = wire::take_u16be(&bytes[17..19]).map_err(wire_err)?;
    match family {
        ADDR_FAMILY_NONE => {
            if raw.iter().any(|byte| *byte != 0) || port != 0 {
                return Err("absent listen addr must zero its address bytes".to_string());
            }
            Ok(None)
        }
        ADDR_FAMILY_V4 => {
            if raw[4..].iter().any(|byte| *byte != 0) {
                return Err("ipv4 listen addr must zero its trailing bytes".to_string());
            }
            let octets = [raw[0], raw[1], raw[2], raw[3]];
            Ok(Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                port,
            )))
        }
        ADDR_FAMILY_V6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(raw);
            Ok(Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            )))
        }
        other => Err(format!("unknown listen addr family {other}")),
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
