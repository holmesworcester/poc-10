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
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::DeviceInviteFact;

pub(crate) struct DeviceInviteAuthenticator;

impl DecodedAuthenticator<super::Codec> for DeviceInviteAuthenticator {
    type Authenticated = DeviceInviteFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        device_invite: DeviceInviteFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_device_invite(fact, device_invite))
    }
}

fn prove_decoded_device_invite(
    fact: &Fact,
    device_invite: DeviceInviteFact,
) -> Result<DeviceInviteFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    verify_signature(&device_invite)?;
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

pub fn verify_signature(fact: &DeviceInviteFact) -> Result<(), String> {
    crate::core::crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &crate::protocol::canonical::encode_with_zeroed_trailing_signature(
            fact,
            super::encode::encode_fact,
        )?,
        &fact.signature,
        "device invite",
    )
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::auth::device_invite::author::signed_device_invite_fact;
    use crate::protocol::auth::device_invite::fact::DeviceInviteFact;

    use super::DeviceInviteAuthenticator;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        signed_device_invite_fact(100, [1; 32], [2; 32], None, [3; 32], [4; 32], SIGNER_KEY)
            .expect("signed device_invite fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, DeviceInviteFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => DeviceInviteAuthenticator::authenticate_decoded(
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
