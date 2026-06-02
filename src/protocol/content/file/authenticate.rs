//! Content-file authenticator.
//!
//! POLICY. Authenticating a `content_file` fact proves, over its signed bytes
//! alone:
//!   1. LAYOUT. The bytes decode to a canonical content-file descriptor.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!   4. FIELDS. The selector ids are non-zero and the blob/slice descriptor is
//!      internally consistent: size within the limit, slice count and budget
//!      matching the fixed slot and the blob-bytes ceiling.
//!
//! Admission scope is unsigned local metadata, not part of these bytes, so the
//! workspace-scope check is interpretation the projector owns. The parent
//! message, deletion gates, and author are proven from other facts, also in the
//! projector.

use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::MAX_FILE_BYTES;
use crate::protocol::content::file_slice::fact::FILE_SLICE_PLAINTEXT_BYTES;

pub(crate) struct ContentFileAuthenticator;

impl Authenticator for ContentFileAuthenticator {
    type Authenticated = super::fact::ContentFileFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_file(fact))
    }
}

/// Prove a content-file fact authentic over its own bytes.
fn authenticate_file(fact: &Fact) -> Result<super::fact::ContentFileFact, String> {
    // 1. Layout.
    let file = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&file)?;
    // 4. Intrinsic descriptor fields.
    validate_file_fields(&file)?;
    Ok(file)
}

pub(super) fn validate_file_fields(file: &super::fact::ContentFileFact) -> Result<(), String> {
    validate_id("file workspace_id", &file.workspace_id)?;
    validate_id("file message_id", &file.message_id)?;
    validate_id("file author_user_id", &file.author_user_id)?;
    validate_id("file file_id", &file.file_id)?;
    if file.blob_bytes > MAX_FILE_BYTES {
        return Err("file size exceeds the 10 GiB limit".to_string());
    }
    if file.blob_bytes == 0 {
        if file.total_slices != 0 {
            return Err("zero-byte file must declare zero slices".to_string());
        }
        return Ok(());
    }
    if file.total_slices == 0 {
        return Err("non-empty file must declare at least one slice".to_string());
    }
    if file.slice_bytes == 0 {
        return Err("non-empty file must declare a slice budget".to_string());
    }
    if file.slice_bytes != FILE_SLICE_PLAINTEXT_BYTES as u32 {
        return Err("file slice budget must match the fixed file-slice slot".to_string());
    }
    let expected: u32 = file
        .blob_bytes
        .div_ceil(file.slice_bytes as u64)
        .try_into()
        .map_err(|_| "slice count overflows u32".to_string())?;
    if file.total_slices != expected {
        return Err(format!(
            "total_slices {} does not match blob_bytes / slice_bytes ceiling {}",
            file.total_slices, expected
        ));
    }
    Ok(())
}

fn validate_id(name: &str, id: &[u8; 32]) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::content::file::create::signed_file_fact;
    use crate::protocol::content::file::fact::{ContentFileFact, SealedMetadata};

    use super::ContentFileAuthenticator;

    const PRIVATE_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        signed_file_fact(
            [1; 32],
            100,
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            1_048_576,
            4,
            262_144,
            [6; 32],
            SealedMetadata::new(b"sealed-filename-and-mime").expect("sealed metadata"),
            PRIVATE_KEY,
        )
        .expect("signed content file fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ContentFileFact> {
        ContentFileAuthenticator::authenticate(fact, &ProjectionContext::default())
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
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
    }

    #[test]
    fn rejects_truncated_bytes() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes.pop();
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
    }

    #[test]
    fn rejects_tampered_signature() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
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
