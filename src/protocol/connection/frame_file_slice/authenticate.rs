//! File-slice connection-frame authenticator.
//!
//! POLICY. Authenticating a `connection_frame_file_slice` fact proves, over its
//! bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical file-slice connection-frame
//!      payload.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! Frame facts carry only wire bytes; there is no fact-boundary signature and no
//! intrinsic field rule. Admission scope, the observation and connection context,
//! decryption, and child materialization are all interpretation the projector
//! owns through `project.rs`.

use crate::core::facts::Fact;
use crate::core::pipeline::{verify_fact_id, ProjectionContext};

use super::fact::ConnectionFrameFileSliceFact;

pub(crate) fn authenticate(
    fact: &Fact,
    input: ConnectionFrameFileSliceFact,
    _context: &ProjectionContext,
) -> Result<ConnectionFrameFileSliceFact, String> {
    prove_decoded_frame_file_slice(fact, input)
}

fn prove_decoded_frame_file_slice(
    fact: &Fact,
    input: ConnectionFrameFileSliceFact,
) -> Result<ConnectionFrameFileSliceFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(input)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::ProjectionContext;
    use crate::core::wire::FixedBytes;
    use crate::protocol::connection::frame_file_slice::author::fact_from_wire;
    use crate::protocol::connection::frame_file_slice::encode as frame_encode;
    use crate::protocol::connection::frame_file_slice::fact::ConnectionFrameFileSliceFact;

    fn canonical_fact() -> Fact {
        let frame =
            frame_encode::encode_frame_bytes(FixedBytes([1; 32]), FixedBytes([2; 24]), &[3; 32])
                .expect("frame bytes");
        fact_from_wire(&frame, 100).expect("connection_frame_file_slice fact")
    }

    fn authenticate(fact: &Fact) -> Result<ConnectionFrameFileSliceFact, String> {
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
