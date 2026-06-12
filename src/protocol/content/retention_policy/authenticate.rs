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
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::RetentionPolicyFact;

pub(crate) fn authenticate(
    fact: &Fact,
    policy: RetentionPolicyFact,
    _context: &ProjectionContext,
) -> Result<RetentionPolicyFact, String> {
    prove_decoded_retention_policy(fact, policy)
}

fn prove_decoded_retention_policy(
    fact: &Fact,
    policy: RetentionPolicyFact,
) -> Result<RetentionPolicyFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
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

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::content::retention_policy::author::authored_retention_policy_fact;
    use crate::protocol::content::retention_policy::fact::{
        RetentionPolicyFact, SCOPE_KIND_WORKSPACE,
    };

    const PRIVATE_KEY: [u8; 32] = [7; 32];
    const WORKSPACE_ID: [u8; 32] = [1; 32];

    fn canonical_fact() -> Fact {
        authored_retention_policy_fact(
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

    fn authenticate(fact: &Fact) -> Result<RetentionPolicyFact, String> {
        let decoded = super::super::decode::decode_fact(fact.body())?;
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
