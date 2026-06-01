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
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::WorkspaceFact;

pub(crate) struct WorkspaceAuthenticator;

impl Authenticator for WorkspaceAuthenticator {
    type Authenticated = WorkspaceFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_workspace(fact))
    }
}

fn authenticate_workspace(fact: &Fact) -> Result<WorkspaceFact, String> {
    // 1. Layout.
    let workspace = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&workspace)?;
    Ok(workspace)
}
