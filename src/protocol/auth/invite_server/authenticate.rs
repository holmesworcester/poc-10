//! Invite-server authenticator.
//!
//! POLICY. Authenticating an `invite_server` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical invite-server fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!   4. FIELDS. The workspace, authority, and public-key selectors are non-zero.
//!
//! Scope (`Global`) and the authority path (bootstrap vs delegated grant) are
//! interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::InviteServerFact;

pub(crate) struct InviteServerAuthenticator;

impl Authenticator for InviteServerAuthenticator {
    type Authenticated = InviteServerFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_invite_server(fact))
    }
}

fn authenticate_invite_server(fact: &Fact) -> Result<InviteServerFact, String> {
    // 1. Layout.
    let invite_server = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&invite_server)?;
    // 4. Non-zero selector fields.
    if invite_server.workspace_id == [0; 32] {
        return Err("invite_server fact has empty workspace_id".to_string());
    }
    if invite_server.authority_fact_id == [0; 32] {
        return Err("invite_server fact has empty authority_fact_id".to_string());
    }
    if invite_server.public_key == [0; 32] {
        return Err("invite_server fact has empty public_key".to_string());
    }
    Ok(invite_server)
}
