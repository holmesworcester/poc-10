pub mod decode {
    //! Byte decoding for invite-secret facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, field order, and the
    //! internally consistent hash/scope fields. Id checks live in
    //! the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{FACT_BYTES, TYPE_INVITE_SECRET};
    use super::super::fact::InviteSecretFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<InviteSecretFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_INVITE_SECRET {
            return Err("expected invite_secret fact".to_string());
        }
        let mut bootstrap_hash = [0; 32];
        bootstrap_hash.copy_from_slice(&bytes[1..33]);
        let mut bootstrap_secret = [0; 32];
        bootstrap_secret.copy_from_slice(&bytes[33..65]);
        let mut workspace_raw = [0; 32];
        workspace_raw.copy_from_slice(&bytes[65..97]);
        let mut invite_raw = [0; 32];
        invite_raw.copy_from_slice(&bytes[97..129]);
        let workspace_id = optional_id(workspace_raw);
        let invite_fact_id = optional_id(invite_raw);
        InviteSecretFact {
            bootstrap_hash,
            bootstrap_secret,
            workspace_id,
            invite_fact_id,
        }
        .validate()
    }

    fn optional_id(id: [u8; 32]) -> Option<[u8; 32]> {
        if id == [0; 32] {
            None
        } else {
            Some(id)
        }
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests.
    //
    // Invariants:
    // - Invite-secret bytes have one fixed-width representation.
    // - Unscoped and scoped secrets preserve their hash, secret, workspace id, and
    //   invite id fields.
    // - Decode rejects internally inconsistent secret/hash or partial-scope shapes.
    //
    // The tests read from complete layouts to increasingly narrow layout guards.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::invite_secret::encode::{encode_fact, FACT_BYTES};

        #[test]
        fn invite_secret_fact_roundtrips_fixed_width() {
            let fact = InviteSecretFact::new([7; 32]);
            let encoded = encode_fact(&fact).expect("encode");
            assert_eq!(encoded.len(), FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact);
        }

        #[test]
        fn invite_secret_fact_roundtrips_scoped() {
            let fact = InviteSecretFact::scoped([7; 32], [1; 32], [2; 32]);
            let encoded = encode_fact(&fact).expect("encode");
            let decoded = decode_fact(&encoded).expect("decode");
            assert_eq!(decoded.workspace_id, Some([1; 32]));
            assert_eq!(decoded.invite_fact_id, Some([2; 32]));
        }

        #[test]
        fn decode_rejects_hash_secret_mismatch() {
            let fact = InviteSecretFact {
                bootstrap_hash: [9; 32],
                bootstrap_secret: [7; 32],
                workspace_id: None,
                invite_fact_id: None,
            };
            let encoded = encode_fact(&fact).expect("encode");
            let err = decode_fact(&encoded).expect_err("mismatched hash must fail");
            assert_eq!(err, "invite secret hash does not match secret");
        }

        #[test]
        fn decode_rejects_incomplete_scope() {
            let fact = InviteSecretFact {
                workspace_id: Some([1; 32]),
                ..InviteSecretFact::new([7; 32])
            };
            let encoded = encode_fact(&fact).expect("encode");
            let err = decode_fact(&encoded).expect_err("incomplete scope must fail");
            assert_eq!(err, "invite secret scope is incomplete");
        }

        #[test]
        fn rejects_wrong_tag() {
            let mut encoded = encode_fact(&InviteSecretFact::new([7; 32])).expect("encode");
            encoded[0] = 0;
            assert!(decode_fact(&encoded).is_err());
        }
    }
}
pub mod authenticate {
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
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::InviteSecretFact;

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

    // Tests.
    //
    // Invariants:
    // - Authentication admits a canonical local bootstrap secret fact.
    // - The fact id is bound to the canonical bytes.
    // - Layout failures stay delegated to the decode layer and still reject at the
    //   authentication boundary.
    //
    // The tests read from the canonical admission proof to id and layout guards.
    #[cfg(test)]
    mod tests {
        use crate::core::facts::{Fact, FactScope};
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::invite_secret::encode;
        use crate::protocol::auth::invite_secret::fact::InviteSecretFact;

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
    }
}
pub mod adapt {
    //! Invite-secret semantic adapter.
    //!
    //! The current invite wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::InviteSecretFact;

    pub(crate) fn adapt(source: InviteSecretFact) -> Result<InviteSecretFact, String> {
        Ok(source)
    }
}

// Poc-10 invite-secret projector.
//
// POLICY. An invite_secret fact is admitted iff:
//   1. STRUCTURAL. The fact is local-only and the invite-secret payload
//      decodes with internally consistent hash/scope fields.
//   2. CONTEXT. No remote context is accepted; this is local bootstrap secret
//      material.
//   3. MATERIALIZE. Write the invite_secret row and publish both auth and
//      connection invite-secret context offers.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};

use super::invite_secret_row;

/// Projector route metadata for the invite fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::invite_secret::project::InviteSecretProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct InviteSecretProjector;

impl InviteSecretProjector {
    pub fn new() -> Self {
        Self
    }
}

// Tests.
//
// Invariants:
// - Invite-secret projection is local bootstrap material: it accepts only Local
//   scope and does not wait on remote context.
// - A projected secret publishes both auth and connection invite-secret context
//   keyed by its own fact id.
// - Projection writes the invite-secret row without emitting intents, time wakes,
//   or purges.
//
// The tests prove the local-only materialization contract, then the scope guard.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::ContextOffer;
    use crate::core::intents::RowMutation;
    use crate::protocol::auth::invite_secret::encode;
    use crate::protocol::auth::invite_secret::fact::InviteSecretFact;
    use crate::protocol::auth::invite_secret::INVITE_SECRET_ROWS;

    fn scoped_secret_fact() -> (Fact, InviteSecretFact) {
        let secret = InviteSecretFact::scoped([7; 32], [1; 32], [2; 32]);
        let fact = Fact::new(
            FactScope::Local,
            100,
            encode::encode_fact(&secret).expect("encode invite secret"),
        );
        (fact, secret)
    }

    #[test]
    fn local_invite_secret_projects_two_context_offers_and_row() {
        let (fact, secret) = scoped_secret_fact();

        let output = InviteSecretProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project invite secret");

        assert!(output.needs.is_empty());
        assert_eq!(
            output.offers,
            vec![
                ContextOffer::range(
                    fact.id,
                    "auth_invite_secret",
                    FactScope::Global,
                    fact.id,
                    fact.id,
                    fact.bytes.clone()
                ),
                ContextOffer::range(
                    fact.id,
                    "connection_invite_secret",
                    FactScope::Local,
                    fact.id,
                    fact.id,
                    fact.bytes.clone()
                ),
            ]
        );
        assert_eq!(
            output.effects.row_mutations,
            vec![RowMutation::InsertValues(invite_secret_row(&secret))]
        );
        let RowMutation::InsertValues(insert) = &output.effects.row_mutations[0] else {
            panic!("invite secret projector should insert its row");
        };
        assert_eq!(insert.table, INVITE_SECRET_ROWS);
        assert!(output.effects.intents.is_empty());
        assert!(output.effects.purged_facts.is_empty());
        assert!(output.time_wakes.is_empty());
    }

    #[test]
    fn invite_secret_projection_rejects_non_local_scope() {
        let (canonical, _) = scoped_secret_fact();
        let non_local = Fact {
            scope: FactScope::Global,
            ..canonical
        };

        let err = InviteSecretProjector::new()
            .project(&non_local, &ProjectionContext::default())
            .expect_err("non-local invite secret should reject");

        assert_eq!(err, "invite_secret fact must have local scope");
    }
}

impl Projector for InviteSecretProjector {
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

impl InviteSecretProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        invite_secret: super::fact::InviteSecretFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("invite_secret fact must have local scope".to_string());
        }
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_invite_secret",
                crate::core::facts::FactScope::Global,
                fact.id,
                fact.id,
                fact.bytes.clone(),
            ))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "connection_invite_secret",
                crate::core::facts::FactScope::Local,
                fact.id,
                fact.id,
                fact.bytes.clone(),
            ))
            .row_mutation(RowMutation::InsertValues(invite_secret_row(&invite_secret))))
    }
}
