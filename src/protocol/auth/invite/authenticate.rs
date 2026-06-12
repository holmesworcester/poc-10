//! Invite-secret authenticator.
//!
//! POLICY. Authenticating an `invite_secret` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical invite-secret fact with
//!      internally consistent hash/scope fields.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local bootstrap secrets, not a signed shared proof, so there is no
//! fact-boundary signature. Admission scope (`Local`) is interpretation the
//! projector owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::InviteSecretFact;

pub(crate) fn authenticate(
    fact: &Fact,
    invite_secret: InviteSecretFact,
    _context: &ProjectionContext,
) -> Result<InviteSecretFact, String> {
    prove_decoded_invite_secret(fact, invite_secret)
}

fn prove_decoded_invite_secret(
    fact: &Fact,
    invite_secret: InviteSecretFact,
) -> Result<InviteSecretFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(invite_secret)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::ProjectionContext;
    use crate::protocol::auth::invite::encode;
    use crate::protocol::auth::invite::fact::InviteSecretFact;

    fn canonical_fact() -> Fact {
        let invite_secret = InviteSecretFact::new([7; 32]);
        let bytes = encode::encode_fact(&invite_secret).expect("encode invite_secret");
        Fact::new(FactScope::Local, 100, bytes)
    }

    fn authenticate(fact: &Fact) -> Result<InviteSecretFact, String> {
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
