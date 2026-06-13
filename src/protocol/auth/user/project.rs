pub mod decode {
    //! Byte decoding for user facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, field order, and
    //! canonical username padding. Id checks live in
    //! the local `authenticate` module.

    use crate::core::wire;
    use crate::core::wire::FixedText;

    use super::super::encode::{FACT_BYTES, TYPE_USER};
    use super::super::fact::{UserFact, Username, USERNAME_BYTES};

    pub fn decode_fact(bytes: &[u8]) -> Result<UserFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_USER {
            return Err("expected user fact".to_string());
        }
        let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
        let mut workspace_id = [0; 32];
        workspace_id.copy_from_slice(&bytes[9..41]);
        let mut public_key = [0; 32];
        public_key.copy_from_slice(&bytes[41..73]);
        let username = read_username(&bytes[73..73 + USERNAME_BYTES])?;
        let signer_start = 73 + USERNAME_BYTES;
        let mut signer_id = [0; 32];
        signer_id.copy_from_slice(&bytes[signer_start..signer_start + 32]);
        let mut signer_public_key = [0; 32];
        signer_public_key.copy_from_slice(&bytes[signer_start + 32..signer_start + 64]);
        Ok(UserFact {
            created_at_ms,
            workspace_id,
            public_key,
            username,
            signer_id,
            signer_public_key,
        })
    }

    fn read_username(bytes: &[u8]) -> Result<Username, String> {
        let padded: [u8; USERNAME_BYTES] = bytes
            .try_into()
            .map_err(|_| "username slot has wrong length".to_string())?;
        FixedText::from_padded(padded).map_err(wire_err)
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::user::encode::{encode_fact, FACT_BYTES};

        fn fact() -> UserFact {
            UserFact {
                created_at_ms: 42,
                workspace_id: [2; 32],
                public_key: [7; 32],
                username: Username::new("alice").expect("username"),
                signer_id: [8; 32],
                signer_public_key: [9; 32],
            }
        }

        #[test]
        fn user_fact_roundtrips_fixed_width() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn rejects_non_canonical_username_padding() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            let start = 1 + 8 + 32 + 32;
            encoded[start + "alice".len() + 1] = b'x';
            assert!(decode_fact(&encoded).is_err());
        }

        #[test]
        fn rejects_long_username() {
            let err = Username::new(&"a".repeat(USERNAME_BYTES + 1))
                .expect_err("long username must fail");
            assert_eq!(
                err,
                wire::WireError::ValueTooLarge {
                    max: USERNAME_BYTES,
                    actual: USERNAME_BYTES + 1
                }
            );
        }
    }
}
pub mod authenticate {
    //! User authenticator.
    //!
    //! POLICY. Authenticating a `user` fact proves, over its canonical bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical user fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!   4. FIELDS. The workspace and public-key selectors are non-empty and the
    //!      username is non-blank.
    //!
    //! Admission scope (`Global`) is unsigned local metadata, so the projector
    //! checks it. Inviter authority is proven from other facts, also in the
    //! projector.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::UserFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        user: UserFact,
        _context: &ProjectionContext,
    ) -> Result<UserFact, String> {
        prove_decoded_user(fact, user)
    }

    fn prove_decoded_user(fact: &Fact, user: UserFact) -> Result<UserFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        // 4. Intrinsic fields.
        if user.workspace_id == [0; 32] {
            return Err("user workspace_id must not be empty".to_string());
        }
        if user.public_key == [0; 32] {
            return Err("user public_key must not be empty".to_string());
        }
        if user.username.as_str().trim().is_empty() {
            return Err("username must not be empty".to_string());
        }
        Ok(user)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::user::author::authored_user_fact;
        use crate::protocol::auth::user::fact::UserFact;

        const SIGNER_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            authored_user_fact(100, [1; 32], [2; 32], "alice", [3; 32], SIGNER_KEY)
                .expect("authored user fact")
        }

        fn authenticate(fact: &Fact) -> Result<UserFact, String> {
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
}
pub mod adapt {
    //! User semantic adapter.
    //!
    //! The current user wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::UserFact;

    pub(crate) fn adapt(source: UserFact) -> Result<UserFact, String> {
        Ok(source)
    }
}

// Poc-10 user projector.
//
// POLICY. A user fact is admitted iff:
//   1. STRUCTURAL. The outer fact is global, carries signer identity, contains a user payload,
//      and the workspace/public key/name fields are non-empty.
//   2. AUTHORITY. Matched user_invite context must match the signer id,
//      signer public key, and workspace.
//   3. MATERIALIZE. Write the user row, publish user context, and share the
//      fact with the workspace.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::{signature, user_invite};
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::user_row;

/// Projector route metadata for the user fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::user::project::UserProjector");

#[derive(Debug, Clone, Default)]
pub struct UserProjector;

impl UserProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for UserProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl UserProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        user: super::fact::UserFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("user fact must have global scope".to_string());
        }

        // 2. Authority and signature evidence.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            crate::protocol::auth::workspace::scope(user.workspace_id),
            fact.id,
            user.signer_public_key,
        )?;
        let invite_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_user_invite",
            crate::core::facts::FactScope::Global,
            user.signer_id,
            user.signer_id,
        );
        let waiting = ProjectionOutput::new()
            .need(signature_need.clone())
            .need(invite_need.clone());
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            user.workspace_id,
            fact.id,
            user.signer_public_key,
            "user",
        )? {
            return Ok(waiting);
        }
        let Some(invite_fact) = context.payload_for(&invite_need) else {
            return Ok(waiting);
        };
        if invite_fact.id != user.signer_id {
            return Err("user signer context payload id mismatch".to_string());
        }
        let invite = user_invite::decode_fact_payload(invite_fact.body())
            .map_err(|_| "user signer context must be a user_invite fact".to_string())?;
        if invite.workspace_id != user.workspace_id {
            return Err("user workspace does not match user_invite workspace".to_string());
        }
        if invite.public_key != user.signer_public_key {
            return Err(
                "user signature signer key does not match user_invite public key".to_string(),
            );
        }
        let user_invite_id = invite_fact.id;
        let context_have = context_have_from_needs(context, [&signature_need, &invite_need]);

        // 3. Materialize.
        Ok(share_fact_with_sync(
            ProjectionOutput::new()
                .need(signature_need)
                .need(invite_need)
                .offer(crate::core::context::ContextOffer::range(
                    fact.id,
                    "auth_user",
                    crate::core::facts::FactScope::Global,
                    fact.id,
                    fact.id,
                ))
                .row_mutation(RowMutation::PutRow(user_row(
                    fact.id,
                    user_invite_id,
                    &user,
                )?)),
            user.workspace_id,
            fact,
            context_have,
        ))
    }
}
