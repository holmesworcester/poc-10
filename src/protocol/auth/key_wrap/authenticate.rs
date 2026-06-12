//! Key-wrap authenticator.
//!
//! POLICY. Authenticating a `key_wrap` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical key-wrap fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! A key wrap is the raw exception to natural fact signing: it carries no
//! signature field, so there is nothing to verify at the fact boundary. The
//! signer is proven from recipient/frontier/endpoint context, and admission
//! scope is unsigned local metadata — both are interpretation the projector
//! owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::KeyWrapFact;

pub(crate) fn authenticate(
    fact: &Fact,
    wrap: KeyWrapFact,
    _context: &ProjectionContext,
) -> Result<KeyWrapFact, String> {
    prove_decoded_key_wrap(fact, wrap)
}

fn prove_decoded_key_wrap(fact: &Fact, wrap: KeyWrapFact) -> Result<KeyWrapFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(wrap)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::{X25519_PUBLIC_KEY_BYTES, XCHACHA20_POLY1305_NONCE_BYTES};
    use crate::core::facts::Fact;
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::auth::key_wrap::author::admit_key_wrap_fact;
    use crate::protocol::auth::key_wrap::encode;
    use crate::protocol::auth::key_wrap::fact::{
        KeyWrapFact, WrappedSecretKind, KEY_WRAP_CIPHERTEXT_BYTES,
    };

    fn canonical_fact() -> Fact {
        let wrap = KeyWrapFact {
            workspace_id: [1; 32],
            created_at_ms: 1_700_000_321,
            signer_endpoint_id: [2; 32],
            frontier_id: [3; 32],
            wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
            wrapped_secret_id: [4; 32],
            wrapped_source_secret_id: [0; 32],
            wrapped_tombstone_node_id: [0; 32],
            range_start: 0,
            range_width: 0,
            bit_depth: 0,
            fact_id_prefix: [0; 32],
            recipient_key_id: [5; 32],
            sender_wrap_public_key: [6; X25519_PUBLIC_KEY_BYTES],
            nonce: [7; XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [8; KEY_WRAP_CIPHERTEXT_BYTES],
        };
        let bytes = encode::encode_key_wrap(&wrap).expect("encode key wrap");
        admit_key_wrap_fact(bytes).expect("admit key wrap fact")
    }

    fn authenticate(fact: &Fact) -> Result<KeyWrapFact, String> {
        let decoded = super::super::decode::decode_key_wrap(fact.body())?;
        super::authenticate(fact, decoded, &ProjectionContext::default())
    }

    fn is_invalid(fact: &Fact) -> bool {
        authenticate(fact).is_err()
    }

    #[test]
    fn authenticates_canonical_fact() {
        assert!(authenticate(&canonical_fact()).is_ok());
    }

    #[test]
    fn rejects_wrong_tag() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes[0] ^= 0xff;
        assert!(is_invalid(&Fact::new(
            canonical.scope,
            canonical.timestamp,
            bytes
        )));
    }

    #[test]
    fn rejects_truncated_bytes() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes.pop();
        assert!(is_invalid(&Fact::new(
            canonical.scope,
            canonical.timestamp,
            bytes
        )));
    }

    #[test]
    fn rejects_id_not_matching_bytes() {
        let canonical = canonical_fact();
        let forged = Fact {
            id: [0; 32],
            scope: canonical.scope.clone(),
            timestamp: canonical.timestamp,
            bytes: canonical.bytes.clone(),
        };
        assert!(is_invalid(&forged));
    }
}
