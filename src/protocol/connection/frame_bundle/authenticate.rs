//! Bundled connection-frame authenticator.
//!
//! POLICY. Authenticating a `connection_frame_bundle` fact proves, over its
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical bundled connection-frame payload.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! Frame facts carry only wire bytes; there is no fact-boundary signature and no
//! intrinsic field rule. Admission scope, the observation and response context,
//! decryption, and child materialization are all interpretation the projector
//! owns through `create::project_observed_frame`.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ConnectionFrameBundleFact;

pub(crate) struct ConnectionFrameBundleAuthenticator;

impl Authenticator for ConnectionFrameBundleAuthenticator {
    type Authenticated = ConnectionFrameBundleFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_frame_bundle(fact))
    }
}

fn authenticate_frame_bundle(fact: &Fact) -> Result<ConnectionFrameBundleFact, String> {
    // 1. Layout.
    let input = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(input)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::core::wire::FixedBytes;
    use crate::protocol::connection::frame_bundle::create::fact_from_wire;
    use crate::protocol::connection::frame_bundle::fact::ConnectionFrameBundleFact;
    use crate::protocol::connection_frame_wire as wire;

    use super::ConnectionFrameBundleAuthenticator;

    fn canonical_fact() -> Fact {
        let frame = wire::encode_frame_bytes(
            wire::CONNECTION_FRAME_SIZE_CLASS_BUNDLE,
            FixedBytes([1; 32]),
            FixedBytes([2; 24]),
            &[3; 32],
        )
        .expect("frame bytes");
        fact_from_wire(&frame, 100).expect("connection_frame_bundle fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ConnectionFrameBundleFact> {
        ConnectionFrameBundleAuthenticator::authenticate(fact, &ProjectionContext::default())
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
