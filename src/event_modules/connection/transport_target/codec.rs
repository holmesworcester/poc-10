use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::store::{EventRecord, EventScope};
use crate::wire::{Reader, Writer};

use super::types::TransportTargetEvent;

pub const TYPE_TRANSPORT_TARGET: u8 = 130;
const ADDR_IPV4: u8 = 4;
const ADDR_IPV6: u8 = 6;

pub fn encode(event: &TransportTargetEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + 32 + 1 + 16 + 2);
    out.u8(TYPE_TRANSPORT_TARGET);
    out.id(&event.connection_id);
    match event.addr.ip() {
        IpAddr::V4(ip) => {
            out.u8(ADDR_IPV4);
            let mut padded = [0; 16];
            padded[..4].copy_from_slice(&ip.octets());
            out.raw(&padded);
        }
        IpAddr::V6(ip) => {
            out.u8(ADDR_IPV6);
            out.raw(&ip.octets());
        }
    }
    out.u16(event.addr.port());
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<TransportTargetEvent, String> {
    let mut reader = Reader::new(bytes, "transport target");
    let tag = reader.u8()?;
    if tag != TYPE_TRANSPORT_TARGET {
        return Err("expected transport target".to_string());
    }
    let connection_id = reader.id()?;
    let family = reader.u8()?;
    let ip_bytes = reader.bytes(16)?;
    let port = reader.u16()?;
    reader.finish()?;
    let addr = match family {
        ADDR_IPV4 => SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3],
            )),
            port,
        ),
        ADDR_IPV6 => {
            let mut bytes = [0; 16];
            bytes.copy_from_slice(&ip_bytes);
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(bytes)), port)
        }
        _ => return Err("transport target address family is invalid".to_string()),
    };
    Ok(TransportTargetEvent {
        connection_id,
        addr,
    })
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        scope: EventScope::Local,
    })
}
