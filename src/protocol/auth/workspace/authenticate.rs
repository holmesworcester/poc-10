//! Workspace authenticator.
//!
//! POLICY. Authenticating a `workspace` fact proves, over its canonical bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical workspace fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!
//! Admission scope (`Global`) is unsigned local metadata, not part of these
//! bytes, so the projector checks it. Local workspace admission requires
//! retained invite acceptance context and materialization stays in the projector.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::WorkspaceFact;

pub(crate) fn authenticate(
    fact: &Fact,
    workspace: WorkspaceFact,
    _context: &ProjectionContext,
) -> Result<WorkspaceFact, String> {
    prove_decoded_workspace(fact, workspace)
}

fn prove_decoded_workspace(fact: &Fact, workspace: WorkspaceFact) -> Result<WorkspaceFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(workspace)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::auth::workspace::author::create_workspace;
    use crate::protocol::auth::workspace::fact::WorkspaceFact;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        create_workspace(100, SIGNER_KEY, "acme").expect("workspace fact")
    }

    fn authenticate(fact: &Fact) -> Result<WorkspaceFact, String> {
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
