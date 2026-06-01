//! Admin-grant authenticator.
//!
//! POLICY. Authenticating an `admin` fact proves, over its signed bytes alone:
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
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::AdminFact;

pub(crate) struct AdminAuthenticator;

impl Authenticator for AdminAuthenticator {
    type Authenticated = AdminFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_admin(fact))
    }
}

fn authenticate_admin(fact: &Fact) -> Result<AdminFact, String> {
    // 1. Layout.
    let admin = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&admin)?;
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
