//! Content-file-slice authenticator.
//!
//! POLICY. Authenticating a `content_file_slice` fact proves, over its signed
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical content-file-slice fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!
//! Admission scope is unsigned local metadata, not part of these bytes, so the
//! workspace-scope check is interpretation the projector owns. The parent file,
//! the BAO proof over its root hash, and the deletion gates are proven from
//! other facts, also in the projector.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ContentFileSliceFact;

pub(crate) struct ContentFileSliceAuthenticator;

impl Authenticator for ContentFileSliceAuthenticator {
    type Authenticated = ContentFileSliceFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_file_slice(fact))
    }
}

/// Prove a content-file-slice fact authentic over its own bytes.
fn authenticate_file_slice(fact: &Fact) -> Result<ContentFileSliceFact, String> {
    // 1. Layout.
    let slice = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&slice)?;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::content::file_slice::create::signed_file_slice_fact;
    use crate::protocol::content::file_slice::fact::{ContentFileSliceFact, FileSliceProof};

    use super::ContentFileSliceAuthenticator;

    const PRIVATE_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        signed_file_slice_fact(
            [1; 32],
            100,
            [2; 32],
            0,
            [3; 32],
            FileSliceProof::new(b"bao-slice-proof").expect("slice proof"),
            &PRIVATE_KEY,
        )
        .expect("signed content file slice fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ContentFileSliceFact> {
        ContentFileSliceAuthenticator::authenticate(fact, &ProjectionContext::default())
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
