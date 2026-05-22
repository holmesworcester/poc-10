//! Canonical receive-origin address construction.
//!
//! Receive provenance stores the observed peer socket address as canonical
//! `SocketAddr::to_string()` bytes. Ingress can accept the invite-link-friendly
//! `IP_PORT` spelling, but stored facts must use one byte representation.

use std::net::SocketAddr;
use std::str;
use std::str::FromStr;

/// Encode an observed socket address in the one representation admitted by the
/// provenance fact layout.
pub fn canonical_origin_addr_bytes(addr: SocketAddr) -> Vec<u8> {
    addr.to_string().into_bytes()
}

/// Normalize boundary input to canonical socket-address bytes.
pub fn normalize_origin_addr_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = str::from_utf8(bytes)
        .map_err(|_| "transport::transit receive origin addr must be utf-8".to_string())?
        .trim();
    if value.is_empty() {
        return Err("transport::transit receive origin addr cannot be empty".to_string());
    }
    Ok(canonical_origin_addr_bytes(parse_origin_addr(value)?))
}

fn parse_origin_addr(value: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = SocketAddr::from_str(value) {
        return Ok(addr);
    }

    let (host, port) = value
        .rsplit_once('_')
        .ok_or_else(|| "transport::transit receive origin addr must include a port".to_string())?;
    let port = u16::from_str(port)
        .map_err(|_| "transport::transit receive origin addr port is invalid".to_string())?;
    let candidate = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    candidate
        .parse()
        .map_err(|_| "transport::transit receive origin addr is invalid".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_socket_addr_strings() {
        assert_eq!(
            normalize_origin_addr_bytes(b"127.0.0.1:41001").expect("ipv4"),
            b"127.0.0.1:41001"
        );
        assert_eq!(
            normalize_origin_addr_bytes(b"[::1]:41001").expect("ipv6"),
            b"[::1]:41001"
        );
    }

    #[test]
    fn accepts_invite_link_friendly_addr_strings() {
        assert_eq!(
            normalize_origin_addr_bytes(b"127.0.0.1_41001").expect("ipv4"),
            b"127.0.0.1:41001"
        );
        assert_eq!(
            normalize_origin_addr_bytes(b"::1_41001").expect("ipv6"),
            b"[::1]:41001"
        );
    }

    #[test]
    fn rejects_non_socket_origin_strings() {
        assert!(normalize_origin_addr_bytes(b"127.0.0.1").is_err());
        assert!(normalize_origin_addr_bytes(b"localhost_41001").is_err());
        assert!(normalize_origin_addr_bytes(b"127.0.0.1_bad").is_err());
    }
}
