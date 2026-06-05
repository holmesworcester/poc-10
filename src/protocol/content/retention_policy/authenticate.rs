//! Retention-policy authenticator.
//!
//! POLICY. Authenticating a `retention_policy` fact proves, over its signed
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical retention-policy fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The natural signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!   4. FIELDS. TTL and created time are non-zero, and a workspace-scoped policy
//!      names the workspace as its scope id.
//!
//! The authority path (root workspace bootstrap vs admin grant), supersession,
//! and floor tightening are proven from other facts, so they stay in the
//! projector.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::RetentionPolicyFact;

pub(crate) struct RetentionPolicyAuthenticator;

impl DecodedAuthenticator<super::Codec> for RetentionPolicyAuthenticator {
    type Authenticated = RetentionPolicyFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        policy: RetentionPolicyFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_retention_policy(fact, policy))
    }
}

fn prove_decoded_retention_policy(
    fact: &Fact,
    policy: RetentionPolicyFact,
) -> Result<RetentionPolicyFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    verify_signature(&policy)?;
    // 4. Intrinsic fields.
    if policy.ttl_minutes == 0 {
        return Err("retention policy ttl_minutes must be non-zero".to_string());
    }
    if policy.created_at_ms == 0 {
        return Err("retention policy created_at_ms must be non-zero".to_string());
    }
    if policy.scope_kind == super::fact::SCOPE_KIND_WORKSPACE
        && policy.scope_id != policy.workspace_id
    {
        return Err("retention policy workspace-scope id must match workspace_id".to_string());
    }
    Ok(policy)
}

/// Verify the retention policy's natural signature over its canonical envelope.
/// The verifier key is embedded in the fact, so this is a context-free
/// fact-boundary proof.
pub fn verify_signature(fact: &RetentionPolicyFact) -> Result<(), String> {
    crate::core::crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &crate::core::wire::encode_with_zeroed_trailing_field(
            fact,
            super::encode::encode_fact,
            crate::core::crypto::ED25519_SIGNATURE_BYTES,
        )?,
        &fact.signature,
        "retention policy",
    )
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::content::retention_policy::author::signed_retention_policy_fact;
    use crate::protocol::content::retention_policy::fact::{
        RetentionPolicyFact, SCOPE_KIND_WORKSPACE,
    };

    use super::RetentionPolicyAuthenticator;

    const PRIVATE_KEY: [u8; 32] = [7; 32];
    const WORKSPACE_ID: [u8; 32] = [1; 32];

    fn canonical_fact() -> Fact {
        signed_retention_policy_fact(
            WORKSPACE_ID,
            None,
            60,
            10,
            SCOPE_KIND_WORKSPACE,
            WORKSPACE_ID,
            [2; 32],
            [3; 32],
            100,
            PRIVATE_KEY,
        )
        .expect("signed retention policy fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, RetentionPolicyFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => RetentionPolicyAuthenticator::authenticate_decoded(
                fact,
                decoded,
                &ProjectionContext::default(),
            ),
            Err(error) => Authentication::Invalid(error),
        }
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
    fn rejects_tampered_signature() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
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
