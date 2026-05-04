use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol::event_modules::identity::endpoint::types::EndpointId;

use super::types::TransitNonce;

pub const BOOTSTRAP_PURPOSE: &[u8] = b"topo-bootstrap-transit-v1";
pub const CONNECTION_PURPOSE: &[u8] = b"topo-connection-transit-v1";

pub fn encrypt(
    local_secret: &[u8; 32],
    remote_endpoint: &EndpointId,
    purpose: &[u8],
    associated_data: &[u8],
    nonce: &TransitNonce,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let key = derive_key(local_secret, remote_endpoint, purpose)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| "encrypt transit envelope".to_string())
}

pub fn decrypt(
    local_secret: &[u8; 32],
    remote_endpoint: &EndpointId,
    purpose: &[u8],
    associated_data: &[u8],
    nonce: &TransitNonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let key = derive_key(local_secret, remote_endpoint, purpose)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| "decrypt transit envelope".to_string())
}

pub fn nonce() -> TransitNonce {
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn derive_key(
    local_secret: &[u8; 32],
    remote_endpoint: &EndpointId,
    purpose: &[u8],
) -> Result<[u8; 32], String> {
    let secret = StaticSecret::from(*local_secret);
    let remote = PublicKey::from(*remote_endpoint);
    let shared = secret.diffie_hellman(&remote);
    let hkdf = Hkdf::<Sha256>::new(Some(purpose), shared.as_bytes());
    let mut key = [0; 32];
    hkdf.expand(b"topo transit key", &mut key)
        .map_err(|_| "derive transit key".to_string())?;
    Ok(key)
}
