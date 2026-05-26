//! Bootstrap-response fact and sealed network-frame layout.
//!
//! The durable `connection::response` fact remains the canonical handshake
//! state. This family owns the flat local receive fact for the sealed response
//! frame that arrives before an established connection secret exists.

use crate::core::crypto::{
    self, X25519PrivateKey, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES,
    XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::core::wire::{self, FixedLayout, FixedSlot, Reader, Writer};
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::connection::fact_receipt::create::normalize_origin_addr_bytes;
use crate::protocol::connection::fact_receipt::fact::{OriginAddr, ORIGIN_ADDR_BYTES};
use crate::protocol::connection::response;

use super::fact::{ConnectionBootstrapResponseFact, SealedConnectionResponseFrame};

pub const TYPE_CONNECTION_BOOTSTRAP_RESPONSE: u8 = 172;
pub const TYPE_SEALED_CONNECTION_RESPONSE: u8 = 47;

const VERSION: u8 = 1;
const RESPONSE_PURPOSE: &[u8] = b"topo-sealed-connection-response-v1";

const RESPONSE_HEADER_BYTES: usize = 1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;

pub const SEALED_CONNECTION_RESPONSE_BYTES: usize =
    RESPONSE_HEADER_BYTES + response::layout::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

pub const CONNECTION_BOOTSTRAP_RESPONSE_FACT_BYTES: usize =
    1 + 8 + FixedSlot::<ORIGIN_ADDR_BYTES>::LEN + SEALED_CONNECTION_RESPONSE_BYTES;

pub fn encode_fact(fact: &ConnectionBootstrapResponseFact) -> Result<Vec<u8>, String> {
    validate_sealed_connection_response_frame(&fact.sealed_response_frame)?;
    let origin_addr = normalize_origin_addr_bytes(fact.origin_addr.bytes())?;

    let mut writer = Writer::with_capacity(CONNECTION_BOOTSTRAP_RESPONSE_FACT_BYTES);
    writer.u8(TYPE_CONNECTION_BOOTSTRAP_RESPONSE);
    writer.u64be(fact.received_at_local_ms);
    writer
        .fixed_slot::<ORIGIN_ADDR_BYTES>(&origin_addr)
        .map_err(wire_err)?;
    writer.fixed(&fact.sealed_response_frame);
    writer
        .finish_exact(CONNECTION_BOOTSTRAP_RESPONSE_FACT_BYTES)
        .map_err(wire_err)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionBootstrapResponseFact, String> {
    let mut reader = Reader::new(bytes);
    reader
        .expect_len(CONNECTION_BOOTSTRAP_RESPONSE_FACT_BYTES)
        .map_err(wire_err)?;
    reader
        .expect_u8(TYPE_CONNECTION_BOOTSTRAP_RESPONSE)
        .map_err(wire_err)?;
    let received_at_local_ms = reader.u64be().map_err(wire_err)?;
    let origin_addr_bytes = reader.fixed_slot::<ORIGIN_ADDR_BYTES>().map_err(wire_err)?;
    let canonical_origin_addr = normalize_origin_addr_bytes(&origin_addr_bytes)?;
    if canonical_origin_addr != origin_addr_bytes {
        return Err("connection bootstrap response origin addr is not canonical".to_string());
    }
    let sealed_response_frame = reader
        .array::<SEALED_CONNECTION_RESPONSE_BYTES>()
        .map_err(wire_err)?;
    reader.finish().map_err(wire_err)?;
    validate_sealed_connection_response_frame(&sealed_response_frame)?;
    Ok(ConnectionBootstrapResponseFact {
        origin_addr: OriginAddr::new(&origin_addr_bytes).map_err(wire_err)?,
        received_at_local_ms,
        sealed_response_frame,
    })
}

pub fn copy_sealed_connection_response_frame(
    frame: &[u8],
) -> Result<SealedConnectionResponseFrame, String> {
    validate_sealed_connection_response_frame(frame)?;
    let mut out = [0; SEALED_CONNECTION_RESPONSE_BYTES];
    out.copy_from_slice(frame);
    Ok(out)
}

pub fn validate_sealed_connection_response_frame(frame: &[u8]) -> Result<(), String> {
    if frame.len() != SEALED_CONNECTION_RESPONSE_BYTES {
        return Err("sealed connection response has wrong length".to_string());
    }
    if frame[0] != TYPE_SEALED_CONNECTION_RESPONSE || frame[1] != VERSION {
        return Err("sealed connection response has unsupported header".to_string());
    }
    Ok(())
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
    validate_sealed_connection_response_frame(frame)?;
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
    use crate::protocol::connection::fact_receipt::fact::OriginAddr;
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
    fn connection_bootstrap_response_fact_roundtrips_fixed_width() {
        let mut sealed_response_frame = [0; SEALED_CONNECTION_RESPONSE_BYTES];
        sealed_response_frame[0] = TYPE_SEALED_CONNECTION_RESPONSE;
        sealed_response_frame[1] = VERSION;
        let fact = ConnectionBootstrapResponseFact {
            origin_addr: OriginAddr::new(b"127.0.0.1:41001").expect("origin"),
            received_at_local_ms: 123,
            sealed_response_frame,
        };

        let encoded = encode_fact(&fact).expect("encode");

        assert_eq!(encoded.len(), CONNECTION_BOOTSTRAP_RESPONSE_FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact);
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
