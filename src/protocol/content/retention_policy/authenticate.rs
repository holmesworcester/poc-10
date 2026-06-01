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
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::RetentionPolicyFact;

pub(crate) struct RetentionPolicyAuthenticator;

impl Authenticator for RetentionPolicyAuthenticator {
    type Authenticated = RetentionPolicyFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_retention_policy(fact))
    }
}

/// Prove a retention-policy fact authentic over its own bytes.
fn authenticate_retention_policy(fact: &Fact) -> Result<RetentionPolicyFact, String> {
    // 1. Layout.
    let policy = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&policy)?;
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
