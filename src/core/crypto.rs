//! Small facade over real cryptographic primitives.
//!
//! Callers pass semantic context and canonical bytes into this facade.
//! The facade owns primitive selection and low-level library calls, keeping
//! event modules from growing their own hash or signature implementations.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const HASH_BYTES: usize = 32;
pub const ED25519_PRIVATE_KEY_BYTES: usize = 32;
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;

pub type Hash = [u8; HASH_BYTES];
pub type Ed25519PrivateKey = [u8; ED25519_PRIVATE_KEY_BYTES];
pub type Ed25519PublicKey = [u8; ED25519_PUBLIC_KEY_BYTES];
pub type Ed25519Signature = [u8; ED25519_SIGNATURE_BYTES];

pub fn hash(bytes: &[u8]) -> Hash {
    *blake3::hash(bytes).as_bytes()
}

pub fn ed25519_public_key(private_key: &Ed25519PrivateKey) -> Ed25519PublicKey {
    VerifyingKey::from(&SigningKey::from_bytes(private_key)).to_bytes()
}

pub fn ed25519_sign(private_key: &Ed25519PrivateKey, bytes: &[u8]) -> Ed25519Signature {
    SigningKey::from_bytes(private_key).sign(bytes).to_bytes()
}

pub fn ed25519_verify(
    public_key: &Ed25519PublicKey,
    bytes: &[u8],
    signature: &Ed25519Signature,
) -> bool {
    let Ok(public_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let signature = Signature::from_bytes(signature);
    public_key.verify(bytes, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_input_sensitive() {
        let left = hash(b"topo auth graph");
        assert_eq!(left, hash(b"topo auth graph"));
        assert_ne!(left, hash(b"topo auth graph."));
    }

    #[test]
    fn ed25519_signatures_verify_with_matching_key_and_bytes() {
        let private_key = [7; ED25519_PRIVATE_KEY_BYTES];
        let public_key = ed25519_public_key(&private_key);
        let bytes = b"canonical signed envelope bytes";

        let signature = ed25519_sign(&private_key, bytes);

        assert!(ed25519_verify(&public_key, bytes, &signature));
        assert!(!ed25519_verify(&public_key, b"changed bytes", &signature));
        assert!(!ed25519_verify(
            &ed25519_public_key(&[8; ED25519_PRIVATE_KEY_BYTES]),
            bytes,
            &signature
        ));
    }

    #[test]
    fn ed25519_signatures_are_deterministic_for_the_same_key_and_bytes() {
        let private_key = [11; ED25519_PRIVATE_KEY_BYTES];
        let bytes = b"fixed canonical bytes";

        assert_eq!(
            ed25519_sign(&private_key, bytes),
            ed25519_sign(&private_key, bytes)
        );
    }
}
