use crate::wire::{Reader, Writer};

use super::super::types::{ConnectionId, EndpointId, TransitNonce};

const MAGIC: &[u8; 10] = b"TOPOTRANS1";
const TAG_BOOTSTRAP: u8 = 1;
const TAG_CONNECTION: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitEnvelope {
    Bootstrap {
        sender_endpoint: EndpointId,
        recipient_endpoint: EndpointId,
        nonce: TransitNonce,
        ciphertext: Vec<u8>,
    },
    Connection {
        connection_id: ConnectionId,
        sender_endpoint: EndpointId,
        recipient_endpoint: EndpointId,
        nonce: TransitNonce,
        ciphertext: Vec<u8>,
    },
}

pub fn associated_data(envelope: &TransitEnvelope) -> Vec<u8> {
    let mut out = Writer::new();
    out.raw(MAGIC);
    match envelope {
        TransitEnvelope::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext: _,
        } => {
            out.u8(TAG_BOOTSTRAP);
            out.id(sender_endpoint);
            out.id(recipient_endpoint);
            out.raw(nonce);
        }
        TransitEnvelope::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext: _,
        } => {
            out.u8(TAG_CONNECTION);
            out.id(connection_id);
            out.id(sender_endpoint);
            out.id(recipient_endpoint);
            out.raw(nonce);
        }
    }
    out.finish()
}

pub fn encode(envelope: &TransitEnvelope) -> Vec<u8> {
    let mut out = Writer::new();
    out.raw(MAGIC);
    match envelope {
        TransitEnvelope::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            out.u8(TAG_BOOTSTRAP);
            out.id(sender_endpoint);
            out.id(recipient_endpoint);
            out.raw(nonce);
            out.sized_bytes(ciphertext);
        }
        TransitEnvelope::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            out.u8(TAG_CONNECTION);
            out.id(connection_id);
            out.id(sender_endpoint);
            out.id(recipient_endpoint);
            out.raw(nonce);
            out.sized_bytes(ciphertext);
        }
    }
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<TransitEnvelope, String> {
    if !bytes.starts_with(MAGIC) {
        return Err("not a transit envelope".to_string());
    }
    let mut reader = Reader::new(&bytes[MAGIC.len()..], "transit envelope");
    let envelope = match reader.u8()? {
        TAG_BOOTSTRAP => TransitEnvelope::Bootstrap {
            sender_endpoint: reader.id()?,
            recipient_endpoint: reader.id()?,
            nonce: nonce24(&mut reader)?,
            ciphertext: reader.sized_bytes()?,
        },
        TAG_CONNECTION => TransitEnvelope::Connection {
            connection_id: reader.id()?,
            sender_endpoint: reader.id()?,
            recipient_endpoint: reader.id()?,
            nonce: nonce24(&mut reader)?,
            ciphertext: reader.sized_bytes()?,
        },
        other => return Err(format!("unknown transit envelope tag {other}")),
    };
    reader.finish()?;
    Ok(envelope)
}

fn nonce24(reader: &mut Reader<'_>) -> Result<TransitNonce, String> {
    let bytes = reader.bytes(24)?;
    let mut nonce = [0; 24];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}
