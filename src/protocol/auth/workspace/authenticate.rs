//! Workspace authenticator.
//!
//! POLICY. Authenticating a `workspace` fact proves, over its signed bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical workspace fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!
//! Admission scope (`Global`) is unsigned local metadata, not part of these
//! bytes, so the projector checks it. The workspace requires no authority
//! context — it is the root identity object — and materialization stays in the
//! projector.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::WorkspaceFact;

pub(crate) struct WorkspaceAuthenticator;

impl DecodedAuthenticator<super::decode::Codec> for WorkspaceAuthenticator {
    type Authenticated = WorkspaceFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        workspace: WorkspaceFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_workspace(fact, workspace))
    }
}

fn prove_decoded_workspace(fact: &Fact, workspace: WorkspaceFact) -> Result<WorkspaceFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    verify_signature(&workspace)?;
    Ok(workspace)
}

pub fn verify_signature(fact: &WorkspaceFact) -> Result<(), String> {
    crate::core::crypto::ed25519_verify_canonical(
        &fact.public_key,
        &crate::core::wire::encode_with_zeroed_trailing_field(
            fact,
            super::encode::encode_fact,
            crate::core::crypto::ED25519_SIGNATURE_BYTES,
        )?,
        &fact.signature,
        "workspace",
    )
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::auth::workspace::author::create_workspace;
    use crate::protocol::auth::workspace::fact::WorkspaceFact;

    use super::WorkspaceAuthenticator;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        create_workspace(100, SIGNER_KEY, "acme").expect("workspace fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, WorkspaceFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => WorkspaceAuthenticator::authenticate_decoded(
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
