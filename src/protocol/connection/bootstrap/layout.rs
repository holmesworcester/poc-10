//! Sealed bootstrap handshake frame layout.
//!
//! The durable `connection::request` and `connection::response` facts remain
//! canonical local/projection state. Network bootstrap traffic uses these
//! sealed wrappers instead: public headers carry only the ephemeral public key
//! needed to derive the opening key plus a nonce, while the canonical fact
//! bytes travel inside X25519 + XChaCha20-Poly1305.

use crate::core::crypto::{
    self, X25519PrivateKey, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES,
    XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::core::wire::{self, FixedLayout, FixedSlot, Reader, Writer};
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::connection::fact_receipt::create::normalize_origin_addr_bytes;
use crate::protocol::connection::fact_receipt::fact::{OriginAddr, ORIGIN_ADDR_BYTES};
use crate::protocol::connection::{request, response};

use super::fact::ConnectionBootstrapFact;

pub const TYPE_CONNECTION_BOOTSTRAP: u8 = 171;
pub const TYPE_SEALED_CONNECTION_REQUEST: u8 = 46;
pub const TYPE_SEALED_CONNECTION_RESPONSE: u8 = 47;

const VERSION: u8 = 1;
const REQUEST_PURPOSE: &[u8] = b"topo-sealed-connection-request-v1";
const RESPONSE_PURPOSE: &[u8] = b"topo-sealed-connection-response-v1";

const REQUEST_HEADER_BYTES: usize = 1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;
const RESPONSE_HEADER_BYTES: usize = 1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;

pub const SEALED_CONNECTION_REQUEST_BYTES: usize =
    REQUEST_HEADER_BYTES + request::layout::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;
pub const SEALED_CONNECTION_RESPONSE_BYTES: usize =
    RESPONSE_HEADER_BYTES + response::layout::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

pub const SEALED_BOOTSTRAP_FRAME_BYTES: usize =
    if SEALED_CONNECTION_REQUEST_BYTES > SEALED_CONNECTION_RESPONSE_BYTES {
        SEALED_CONNECTION_REQUEST_BYTES
    } else {
        SEALED_CONNECTION_RESPONSE_BYTES
    };
pub const CONNECTION_BOOTSTRAP_FACT_BYTES: usize =
    1 + 8 + FixedSlot::<ORIGIN_ADDR_BYTES>::LEN + FixedSlot::<SEALED_BOOTSTRAP_FRAME_BYTES>::LEN;

pub fn encode_fact(fact: &ConnectionBootstrapFact) -> Result<Vec<u8>, String> {
    validate_sealed_frame(fact.frame.bytes())?;
    let origin_addr = normalize_origin_addr_bytes(fact.origin_addr.bytes())?;

    let mut writer = Writer::with_capacity(CONNECTION_BOOTSTRAP_FACT_BYTES);
    writer.u8(TYPE_CONNECTION_BOOTSTRAP);
    writer.u64be(fact.received_at_local_ms);
    writer
        .fixed_slot::<ORIGIN_ADDR_BYTES>(&origin_addr)
        .map_err(wire_err)?;
    writer.fixed_slot_value(&fact.frame).map_err(wire_err)?;
    writer
        .finish_exact(CONNECTION_BOOTSTRAP_FACT_BYTES)
        .map_err(wire_err)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionBootstrapFact, String> {
    let mut reader = Reader::new(bytes);
    reader
        .expect_len(CONNECTION_BOOTSTRAP_FACT_BYTES)
        .map_err(wire_err)?;
    reader
        .expect_u8(TYPE_CONNECTION_BOOTSTRAP)
        .map_err(wire_err)?;
    let received_at_local_ms = reader.u64be().map_err(wire_err)?;
    let origin_addr_bytes = reader.fixed_slot::<ORIGIN_ADDR_BYTES>().map_err(wire_err)?;
    let canonical_origin_addr = normalize_origin_addr_bytes(&origin_addr_bytes)?;
    if canonical_origin_addr != origin_addr_bytes {
        return Err("connection bootstrap origin addr is not canonical".to_string());
    }
    let frame = reader
        .fixed_slot_value::<SEALED_BOOTSTRAP_FRAME_BYTES>()
        .map_err(wire_err)?;
    reader.finish().map_err(wire_err)?;
    validate_sealed_frame(frame.bytes())?;
    Ok(ConnectionBootstrapFact {
        origin_addr: OriginAddr::new(&origin_addr_bytes).map_err(wire_err)?,
        received_at_local_ms,
        frame,
    })
}

pub fn validate_sealed_frame(frame: &[u8]) -> Result<(), String> {
    match frame.first().copied() {
        Some(TYPE_SEALED_CONNECTION_REQUEST) if frame.len() == SEALED_CONNECTION_REQUEST_BYTES => {
            Ok(())
        }
        Some(TYPE_SEALED_CONNECTION_RESPONSE)
            if frame.len() == SEALED_CONNECTION_RESPONSE_BYTES =>
        {
            Ok(())
        }
        Some(TYPE_SEALED_CONNECTION_REQUEST) => {
            Err("sealed connection request has wrong length".to_string())
        }
        Some(TYPE_SEALED_CONNECTION_RESPONSE) => {
            Err("sealed connection response has wrong length".to_string())
        }
        Some(other) => Err(format!("unknown sealed bootstrap frame tag {other}")),
        None => Err("sealed bootstrap frame is empty".to_string()),
    }
}

pub fn seal_connection_request(
    request_bytes: &[u8],
    initiator_ephemeral_private_key: &X25519PrivateKey,
) -> Result<Vec<u8>, String> {
    let request = request::layout::decode_fact(request_bytes)?;
    if crypto::x25519_public_key(initiator_ephemeral_private_key)
        != request.initiator_ephemeral_public_key
    {
        return Err("sealed connection request ephemeral key does not match request".to_string());
    }

    let nonce = crypto::random_xchacha20poly1305_nonce();
    let header = request_header(request.initiator_ephemeral_public_key, nonce);
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        initiator_ephemeral_private_key,
        &request.to_endpoint,
        REQUEST_PURPOSE,
        &header,
        &nonce,
        request_bytes,
    )?;
    if ciphertext.len() != request::layout::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES {
        return Err("sealed connection request ciphertext length mismatch".to_string());
    }

    let mut out = Vec::with_capacity(SEALED_CONNECTION_REQUEST_BYTES);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open_connection_request(
    frame: &[u8],
    local_endpoint: &EndpointFact,
) -> Result<Vec<u8>, String> {
    if frame.len() != SEALED_CONNECTION_REQUEST_BYTES {
        return Err("sealed connection request has wrong length".to_string());
    }
    if frame[0] != TYPE_SEALED_CONNECTION_REQUEST || frame[1] != VERSION {
        return Err("sealed connection request has unsupported header".to_string());
    }
    let mut initiator_ephemeral_public_key = [0; 32];
    initiator_ephemeral_public_key.copy_from_slice(&frame[2..34]);
    let nonce = nonce_from(&frame[34..58]);
    let header = &frame[..REQUEST_HEADER_BYTES];
    let ciphertext = &frame[REQUEST_HEADER_BYTES..];

    let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
        &local_endpoint.secret,
        &initiator_ephemeral_public_key,
        REQUEST_PURPOSE,
        header,
        &nonce,
        ciphertext,
    )?;
    let request = request::layout::decode_fact(&plaintext)?;
    if request.to_endpoint != local_endpoint.endpoint {
        return Err("sealed connection request is addressed to another endpoint".to_string());
    }
    if request.initiator_ephemeral_public_key != initiator_ephemeral_public_key {
        return Err(
            "sealed connection request inner ephemeral key does not match header".to_string(),
        );
    }
    Ok(plaintext)
}

pub fn seal_connection_response(
    response_bytes: &[u8],
    responder_ephemeral_private_key: &X25519PrivateKey,
) -> Result<Vec<u8>, String> {
    let response = response::layout::decode_fact(response_bytes)?;
    if crypto::x25519_public_key(responder_ephemeral_private_key)
        != response.responder_ephemeral_public_key
    {
        return Err("sealed connection response ephemeral key does not match response".to_string());
    }

    let nonce = crypto::random_xchacha20poly1305_nonce();
    let header = response_header(response.responder_ephemeral_public_key, nonce);
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        responder_ephemeral_private_key,
        &response.to_endpoint,
        RESPONSE_PURPOSE,
        &header,
        &nonce,
        response_bytes,
    )?;
    if ciphertext.len() != response::layout::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES {
        return Err("sealed connection response ciphertext length mismatch".to_string());
    }

    let mut out = Vec::with_capacity(SEALED_CONNECTION_RESPONSE_BYTES);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open_connection_response(
    frame: &[u8],
    local_endpoint: &EndpointFact,
) -> Result<Vec<u8>, String> {
    if frame.len() != SEALED_CONNECTION_RESPONSE_BYTES {
        return Err("sealed connection response has wrong length".to_string());
    }
    if frame[0] != TYPE_SEALED_CONNECTION_RESPONSE || frame[1] != VERSION {
        return Err("sealed connection response has unsupported header".to_string());
    }
    let mut responder_ephemeral_public_key = [0; 32];
    responder_ephemeral_public_key.copy_from_slice(&frame[2..34]);
    let nonce = nonce_from(&frame[34..58]);
    let header = &frame[..RESPONSE_HEADER_BYTES];
    let ciphertext = &frame[RESPONSE_HEADER_BYTES..];

    let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
        &local_endpoint.secret,
        &responder_ephemeral_public_key,
        RESPONSE_PURPOSE,
        header,
        &nonce,
        ciphertext,
    )?;
    let response = response::layout::decode_fact(&plaintext)?;
    if response.to_endpoint != local_endpoint.endpoint {
        return Err("sealed connection response is addressed to another endpoint".to_string());
    }
    if response.responder_ephemeral_public_key != responder_ephemeral_public_key {
        return Err(
            "sealed connection response inner ephemeral key does not match header".to_string(),
        );
    }
    Ok(plaintext)
}

fn request_header(
    initiator_ephemeral_public_key: [u8; 32],
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(REQUEST_HEADER_BYTES);
    out.push(TYPE_SEALED_CONNECTION_REQUEST);
    out.push(VERSION);
    out.extend_from_slice(&initiator_ephemeral_public_key);
    out.extend_from_slice(&nonce);
    out
}

fn response_header(
    responder_ephemeral_public_key: [u8; 32],
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(RESPONSE_HEADER_BYTES);
    out.push(TYPE_SEALED_CONNECTION_RESPONSE);
    out.push(VERSION);
    out.extend_from_slice(&responder_ephemeral_public_key);
    out.extend_from_slice(&nonce);
    out
}

fn nonce_from(bytes: &[u8]) -> XChaCha20Poly1305Nonce {
    let mut nonce = [0; XCHACHA20_POLY1305_NONCE_BYTES];
    nonce.copy_from_slice(bytes);
    nonce
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::{Fact, FactScope};
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::connection::bootstrap::fact::ConnectionBootstrapFact;
    use crate::protocol::connection::fact_receipt::fact::OriginAddr;
    use crate::protocol::connection::request::fact::ConnectionRequestFact;
    use crate::protocol::connection::response::fact::ConnectionResponseFact;

    fn endpoint(secret: [u8; 32]) -> EndpointFact {
        EndpointFact {
            endpoint: crypto::x25519_public_key(&secret),
            secret,
            signing_public_key: crypto::ed25519_public_key(&[91; 32]),
            signing_secret: [91; 32],
        }
    }

    fn contains_id(bytes: &[u8], id: &[u8; 32]) -> bool {
        bytes.windows(id.len()).any(|window| window == id)
    }

    #[test]
    fn connection_bootstrap_fact_roundtrips_fixed_width() {
        let fact = ConnectionBootstrapFact {
            origin_addr: OriginAddr::new(b"127.0.0.1:41001").expect("origin"),
            received_at_local_ms: 123,
            frame: crate::core::wire::FixedSlot::new(&vec![
                TYPE_SEALED_CONNECTION_RESPONSE;
                SEALED_CONNECTION_RESPONSE_BYTES
            ])
            .expect("frame"),
        };

        let encoded = encode_fact(&fact).expect("encode");

        assert_eq!(encoded.len(), CONNECTION_BOOTSTRAP_FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact);
    }

    #[test]
    fn sealed_request_opens_only_for_addressed_endpoint() {
        let responder = endpoint([2; 32]);
        let initiator_ephemeral_private = [3; 32];
        let request = ConnectionRequestFact {
            from_endpoint: crypto::x25519_public_key(&[1; 32]),
            to_endpoint: responder.endpoint,
            nonce: [4; 32],
            invite_fact_id: [5; 32],
            bootstrap_hash: [6; 32],
            invite_signature: [7; crypto::ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: [8; 32],
            initiator_ephemeral_secret_fact_id: [9; 32],
            initiator_ephemeral_public_key: crypto::x25519_public_key(&initiator_ephemeral_private),
            from_listen_addr: Some("127.0.0.1:41001".parse().expect("addr")),
            to_listen_addr: None,
        };
        let bytes = request::layout::encode_fact(&request).expect("request");

        let sealed =
            seal_connection_request(&bytes, &initiator_ephemeral_private).expect("seal request");

        assert_eq!(sealed[0], TYPE_SEALED_CONNECTION_REQUEST);
        assert_eq!(sealed.len(), SEALED_CONNECTION_REQUEST_BYTES);
        assert_ne!(sealed, bytes);
        assert_eq!(
            REQUEST_HEADER_BYTES,
            1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES
        );
        let public_header = &sealed[..REQUEST_HEADER_BYTES];
        assert_eq!(
            &public_header[2..34],
            &request.initiator_ephemeral_public_key
        );
        assert!(!contains_id(public_header, &request.from_endpoint));
        assert!(!contains_id(public_header, &request.to_endpoint));
        assert_eq!(
            open_connection_request(&sealed, &responder).expect("open request"),
            bytes
        );
        assert!(open_connection_request(&sealed, &endpoint([99; 32])).is_err());
    }

    #[test]
    fn sealed_response_hides_connection_secret_and_opens_for_initiator() {
        let initiator = endpoint([11; 32]);
        let responder_ephemeral_private = [12; 32];
        let response = ConnectionResponseFact {
            from_endpoint: crypto::x25519_public_key(&[10; 32]),
            to_endpoint: initiator.endpoint,
            request_id: [13; 32],
            invite_secret_fact_id: [14; 32],
            initiator_ephemeral_secret_fact_id: [15; 32],
            responder_ephemeral_secret_fact_id: [16; 32],
            responder_ephemeral_public_key: crypto::x25519_public_key(&responder_ephemeral_private),
            handshake_hash: [17; 32],
            connection_secret: [18; 32],
        };
        let response_fact = Fact::new(
            FactScope::Local,
            1,
            response::layout::encode_fact(&response).expect("response"),
        );

        let sealed = seal_connection_response(&response_fact.bytes, &responder_ephemeral_private)
            .expect("seal response");

        assert_eq!(sealed[0], TYPE_SEALED_CONNECTION_RESPONSE);
        assert_eq!(sealed.len(), SEALED_CONNECTION_RESPONSE_BYTES);
        assert_eq!(
            RESPONSE_HEADER_BYTES,
            1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES
        );
        let public_header = &sealed[..RESPONSE_HEADER_BYTES];
        assert_eq!(
            &public_header[2..34],
            &response.responder_ephemeral_public_key
        );
        assert!(!contains_id(public_header, &response.from_endpoint));
        assert!(!contains_id(public_header, &response.to_endpoint));
        assert!(!contains_id(public_header, &response.request_id));
        assert!(!sealed
            .windows(response.connection_secret.len())
            .any(|window| window == response.connection_secret));
        assert_eq!(
            open_connection_response(&sealed, &initiator).expect("open response"),
            response_fact.bytes
        );
    }

    #[test]
    fn response_header_tamper_breaks_authentication() {
        let initiator = endpoint([21; 32]);
        let responder_ephemeral_private = [22; 32];
        let response = ConnectionResponseFact {
            from_endpoint: crypto::x25519_public_key(&[20; 32]),
            to_endpoint: initiator.endpoint,
            request_id: [23; 32],
            invite_secret_fact_id: [24; 32],
            initiator_ephemeral_secret_fact_id: [25; 32],
            responder_ephemeral_secret_fact_id: [26; 32],
            responder_ephemeral_public_key: crypto::x25519_public_key(&responder_ephemeral_private),
            handshake_hash: [27; 32],
            connection_secret: [28; 32],
        };
        let bytes = response::layout::encode_fact(&response).expect("response");
        let mut sealed =
            seal_connection_response(&bytes, &responder_ephemeral_private).expect("seal response");

        sealed[2] ^= 0x80;

        assert!(open_connection_response(&sealed, &initiator).is_err());
    }
}
