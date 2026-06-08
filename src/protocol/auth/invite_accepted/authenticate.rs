//! Invite-accepted authenticator.
//!
//! POLICY. Authenticating an `invite_accepted` fact proves, over its bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical invite-accepted fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   FIELDS. The workspace, invite, bootstrap secret/hash, accepted endpoint,
//!      and bootstrap endpoint fields are non-zero, and the hash matches the
//!      retained secret.
//!
//! This is a local membership fact, not a signed shared proof, so there is no
//! fact-boundary signature. Admission scope (`Local`) is interpretation the
//! projector owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};
use crate::protocol::auth::invite::fact::bootstrap_secret_hash;

use super::fact::InviteAcceptedFact;

pub(crate) struct InviteAcceptedAuthenticator;

impl DecodedAuthenticator<super::Codec> for InviteAcceptedAuthenticator {
    type Authenticated = InviteAcceptedFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        accepted: InviteAcceptedFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_invite_accepted(fact, accepted))
    }
}

fn prove_decoded_invite_accepted(
    fact: &Fact,
    accepted: InviteAcceptedFact,
) -> Result<InviteAcceptedFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    // Non-zero fact id fields.
    if accepted.workspace_id == [0; 32]
        || accepted.invite_fact_id == [0; 32]
        || accepted.bootstrap_hash == [0; 32]
        || accepted.bootstrap_secret == [0; 32]
        || accepted.accepted_endpoint_id == [0; 32]
        || accepted.bootstrap_endpoint_id == [0; 32]
    {
        return Err("invite_accepted fact has empty fact id field".to_string());
    }
    if accepted.bootstrap_hash != bootstrap_secret_hash(&accepted.bootstrap_secret) {
        return Err("invite_accepted bootstrap hash does not match secret".to_string());
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::auth::invite::fact::bootstrap_secret_hash;
    use crate::protocol::auth::invite_accepted::encode;
    use crate::protocol::auth::invite_accepted::fact::InviteAcceptedFact;

    use super::InviteAcceptedAuthenticator;

    fn canonical_fact() -> Fact {
        let accepted = InviteAcceptedFact {
            workspace_id: [1; 32],
            invite_fact_id: [2; 32],
            bootstrap_hash: bootstrap_secret_hash(&[7; 32]),
            bootstrap_secret: [7; 32],
            accepted_endpoint_id: [5; 32],
            bootstrap_endpoint_id: [6; 32],
            bootstrap_addr: "127.0.0.1:41000".parse().unwrap(),
            user_authority_fact_id: None,
            endpoint_role: EndpointRole::Device,
            identity_scope: true,
        };
        let bytes = encode::encode_fact(&accepted).expect("encode invite_accepted");
        Fact::new(FactScope::Local, 100, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, InviteAcceptedFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => InviteAcceptedAuthenticator::authenticate_decoded(
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
