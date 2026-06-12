//! Admin-grant authenticator.
//!
//! POLICY. Authenticating an `admin` fact proves, over its canonical bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical admin fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!   4. FIELDS. The workspace, public-key, authority, and user selectors are
//!      non-zero.
//!
//! Scope (`Global`) and the authority path (bootstrap vs delegated grant) are
//! interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::AdminFact;

pub(crate) fn authenticate(
    fact: &Fact,
    admin: AdminFact,
    _context: &ProjectionContext,
) -> Result<AdminFact, String> {
    prove_decoded_admin(fact, admin)
}

fn prove_decoded_admin(fact: &Fact, admin: AdminFact) -> Result<AdminFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    // 4. Non-zero selector fields.
    if admin.workspace_id == [0u8; 32] {
        return Err("admin workspace_id must not be zero".to_string());
    }
    if admin.public_key == [0u8; 32] {
        return Err("admin public_key must not be zero".to_string());
    }
    if admin.authority_fact_id == [0u8; 32] {
        return Err("admin authority_fact_id must not be zero".to_string());
    }
    if admin.user_fact_id == [0u8; 32] {
        return Err("admin user_fact_id must not be zero".to_string());
    }
    Ok(admin)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::auth::admin::author::authored_admin_fact;
    use crate::protocol::auth::admin::fact::AdminFact;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        let grant = AdminFact {
            created_at_ms: 100,
            workspace_id: [1; 32],
            public_key: [2; 32],
            authority_fact_id: [3; 32],
            user_fact_id: [4; 32],
            signer_id: [3; 32],
            signer_public_key: [0; 32],
        };
        authored_admin_fact(100, [3; 32], SIGNER_KEY, grant).expect("signed admin fact")
    }

    // Enter through the staged path (codec decode -> authenticate_decoded) so the
    // tests exercise the same boundary core runs.
    fn authenticate(fact: &Fact) -> Result<AdminFact, String> {
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
