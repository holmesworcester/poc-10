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
use crate::core::projectors::{
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
