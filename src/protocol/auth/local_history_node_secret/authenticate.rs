//! Local history-node secret authenticator.
//!
//! POLICY. Authenticating a `local_history_node_secret` fact proves, over its
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical local history-node secret fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local-only secrets, never signed envelopes, so there is no
//! fact-boundary signature. Admission scope (`Local`), the frontier and source
//! chain, parent/child addressing, retirement, and materialization are all
//! interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::LocalHistoryNodeSecretFact;

pub(crate) struct LocalHistoryNodeSecretAuthenticator;

impl Authenticator for LocalHistoryNodeSecretAuthenticator {
    type Authenticated = LocalHistoryNodeSecretFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_local_history_node_secret(fact))
    }
}

fn authenticate_local_history_node_secret(
    fact: &Fact,
) -> Result<LocalHistoryNodeSecretFact, String> {
    // 1. Layout.
    let node = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(node)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::XCHACHA20_POLY1305_KEY_BYTES;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::auth::local_history_node_secret::fact::LocalHistoryNodeSecretFact;
    use crate::protocol::auth::local_history_node_secret::layout;

    use super::LocalHistoryNodeSecretAuthenticator;

    fn canonical_fact() -> Fact {
        let node = LocalHistoryNodeSecretFact {
            workspace_id: [1; 32],
            frontier_id: [2; 32],
            owner_endpoint_id: [3; 32],
            source_secret_id: [4; 32],
            range_start: 0,
            range_width: 1,
            bit_depth: 256,
            fact_id_prefix: [5; 32],
            tombstone_node_id: [6; 32],
            node_secret: [7; XCHACHA20_POLY1305_KEY_BYTES],
        };
        let bytes = layout::encode_local_history_node_secret(&node)
            .expect("encode local history node secret");
        Fact::new(FactScope::Local, 123, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, LocalHistoryNodeSecretFact> {
        LocalHistoryNodeSecretAuthenticator::authenticate(fact, &ProjectionContext::default())
    }

    fn is_invalid(fact: &Fact) -> bool {
        matches!(authenticate(fact), Authentication::Invalid(_))
    }

    #[test]
    fn authenticates_canonical_fact() {
        assert!(matches!(
            authenticate(&canonical_fact()),
            Authentication::Authenticated(_)
        ));
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
