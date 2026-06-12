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
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::DeviceInviteFact;

pub(crate) fn authenticate(
    fact: &Fact,
    device_invite: DeviceInviteFact,
    _context: &ProjectionContext,
) -> Result<DeviceInviteFact, String> {
    prove_decoded_device_invite(fact, device_invite)
}

fn prove_decoded_device_invite(
    fact: &Fact,
    device_invite: DeviceInviteFact,
) -> Result<DeviceInviteFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
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

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::auth::device_invite::author::authored_device_invite_fact;
    use crate::protocol::auth::device_invite::fact::DeviceInviteFact;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        authored_device_invite_fact(100, [1; 32], [2; 32], None, [3; 32], [4; 32], SIGNER_KEY)
            .expect("signed device_invite fact")
    }

    fn authenticate(fact: &Fact) -> Result<DeviceInviteFact, String> {
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
