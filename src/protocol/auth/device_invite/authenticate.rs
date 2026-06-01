//! Device-invite authenticator.
//!
//! POLICY. Authenticating a `device_invite` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical device-invite fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!   4. FIELDS. The workspace, user-authority, and public-key selectors are
//!      non-zero.
//!
//! Scope (`Global`) and the authority path (user-signed vs endpoint-signed) are
//! interpretation the projector owns.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::DeviceInviteFact;

pub(crate) struct DeviceInviteAuthenticator;

impl Authenticator for DeviceInviteAuthenticator {
    type Authenticated = DeviceInviteFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_device_invite(fact))
    }
}

fn authenticate_device_invite(fact: &Fact) -> Result<DeviceInviteFact, String> {
    // 1. Layout.
    let device_invite = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&device_invite)?;
    // 4. Non-zero selector fields.
    if device_invite.workspace_id == [0; 32] {
        return Err("device_invite fact has empty workspace_id".to_string());
    }
    if device_invite.user_authority_fact_id == [0; 32] {
        return Err("device_invite fact has empty user_authority_fact_id".to_string());
    }
    if device_invite.public_key == [0; 32] {
        return Err("device_invite fact has empty public_key".to_string());
    }
    Ok(device_invite)
}
