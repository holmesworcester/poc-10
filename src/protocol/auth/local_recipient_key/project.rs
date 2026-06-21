pub mod decode {
    //! Byte decoding for local recipient key facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, field order, and that the
    //! decoded material is canonical. Id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{
        validate_local_recipient_key, LOCAL_RECIPIENT_KEY_BYTES, TYPE_LOCAL_RECIPIENT_KEY,
    };
    use super::super::fact::LocalRecipientKeyFact;

    pub fn decode_local_recipient_key(bytes: &[u8]) -> Result<LocalRecipientKeyFact, String> {
        wire::expect_len(bytes, LOCAL_RECIPIENT_KEY_BYTES).map_err(wire_err)?;
        if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_LOCAL_RECIPIENT_KEY {
            return Err("expected local recipient key".to_string());
        }
        let fact = LocalRecipientKeyFact {
            workspace_id: bytes[1..33].try_into().unwrap(),
            recipient_key_id: bytes[33..65].try_into().unwrap(),
            recipient_key: bytes[65..97].try_into().unwrap(),
            recipient_secret: bytes[97..129].try_into().unwrap(),
        };
        validate_local_recipient_key(&fact)?;
        Ok(fact)
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests.
    // Single round-trip test: encode then decode recovers the fact.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::core::crypto::{self, X25519_PRIVATE_KEY_BYTES};
        use crate::protocol::auth::local_recipient_key::encode::{
            encode_local_recipient_key, LOCAL_RECIPIENT_KEY_BYTES,
        };

        fn sample_fact() -> LocalRecipientKeyFact {
            let recipient_secret = [7; X25519_PRIVATE_KEY_BYTES];
            let recipient_key = crypto::x25519_public_key(&recipient_secret);
            LocalRecipientKeyFact {
                workspace_id: [1; 32],
                recipient_key_id: [2; 32],
                recipient_key,
                recipient_secret,
            }
        }

        #[test]
        fn local_recipient_key_roundtrips_fixed_width() {
            let fact = sample_fact();

            let encoded = encode_local_recipient_key(&fact).expect("encode local recipient key");

            assert_eq!(encoded.len(), LOCAL_RECIPIENT_KEY_BYTES);
            assert_eq!(
                decode_local_recipient_key(&encoded).expect("decode local recipient key"),
                fact
            );
        }
    }
}
pub mod authenticate {
    //! Local recipient key authenticator.
    //!
    //! POLICY. Authenticating a `local_recipient_key` fact proves, over its bytes
    //! alone:
    //!   1. LAYOUT. The bytes decode to a canonical local recipient key fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! These are local-only facts, never signed envelopes, so there is no
    //! fact-boundary signature. Admission scope (`Local`), the shared-recipient
    //! match, supersession, and materialization are all interpretation the
    //! projector owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::LocalRecipientKeyFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        local: LocalRecipientKeyFact,
        _context: &ProjectionContext,
    ) -> Result<LocalRecipientKeyFact, String> {
        prove_decoded_local_recipient_key(fact, local)
    }

    fn prove_decoded_local_recipient_key(
        fact: &Fact,
        local: LocalRecipientKeyFact,
    ) -> Result<LocalRecipientKeyFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(local)
    }

    // Tests.
    // Ordered most-central-first: happy-path authentication, then the id guard, then layout guards.
    #[cfg(test)]
    mod tests {
        use crate::core::crypto::{self, X25519_PRIVATE_KEY_BYTES};
        use crate::core::facts::{Fact, FactScope};
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::local_recipient_key::encode;
        use crate::protocol::auth::local_recipient_key::fact::LocalRecipientKeyFact;

        fn canonical_fact() -> Fact {
            let recipient_secret = [7; X25519_PRIVATE_KEY_BYTES];
            let recipient_key = crypto::x25519_public_key(&recipient_secret);
            let local = LocalRecipientKeyFact {
                workspace_id: [1; 32],
                recipient_key_id: [2; 32],
                recipient_key,
                recipient_secret,
            };
            let bytes =
                encode::encode_local_recipient_key(&local).expect("encode local recipient key");
            Fact::new(FactScope::Local, 123, bytes)
        }

        fn authenticate(fact: &Fact) -> Result<LocalRecipientKeyFact, String> {
            let decoded = super::super::decode::decode_local_recipient_key(fact.body())?;
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
    //! Local recipient key semantic adapter.
    //!
    //! The current local_recipient_key wire shape is already the active semantic
    //! shape. This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::LocalRecipientKeyFact;

    pub(crate) fn adapt(source: LocalRecipientKeyFact) -> Result<LocalRecipientKeyFact, String> {
        Ok(source)
    }
}

// Local recipient key projector.
//
// POLICY. A local recipient key is admitted iff it is local-scoped and matches
// its shared recipient fact. Projection offers local-recipient context while the
// key is live, and self-purges when a superseding recipient key retires it.

use crate::core::context::{ContextNeed, ContextOfferClaim};
use crate::core::facts::Fact;
use crate::core::intents::{RowMutation, TableDeleteWhere, TableInsert, Value};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::key_wrap::project::{matched_payload_fact, require_local_scope};
use crate::protocol::auth::recipient_key;

use super::{fact::LocalRecipientKeyFact, LOCAL_RECIPIENT_KEY_ROWS};

/// Projector route metadata for the local_recipient_key fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::local_recipient_key::project::LocalRecipientKeyProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct LocalRecipientKeyProjector;

impl LocalRecipientKeyProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for LocalRecipientKeyProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_local_recipient_key(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl LocalRecipientKeyProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        local: LocalRecipientKeyFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        local_recipient_key(fact, context, local)
    }
}

fn local_recipient_key(
    fact: &Fact,
    projection_context: &ProjectionContext,
    local: LocalRecipientKeyFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    let scope = crate::protocol::auth::workspace::scope(local.workspace_id);
    require_local_scope(fact)?;

    // 2. Context: recipient match and supersession.
    let recipient_need = ContextNeed::range(
        fact.id,
        "recipient_key",
        scope.clone(),
        local.recipient_key_id,
        local.recipient_key_id,
    );
    let Some(recipient_fact) = matched_payload_fact(projection_context, &recipient_need) else {
        return Ok(ProjectionOutput::new().need(recipient_need));
    };
    let recipient = recipient_key::decode_fact_payload(&recipient_fact.bytes)?;
    if recipient.workspace_id != local.workspace_id {
        return Err("local recipient key workspace does not match recipient".to_string());
    }
    if recipient.recipient_key != local.recipient_key {
        return Err("local recipient key public key does not match recipient".to_string());
    }

    let superseded_need = ContextNeed::range(
        fact.id,
        "recipient_superseded",
        scope.clone(),
        local.recipient_key_id,
        local.recipient_key_id,
    );
    let is_superseded = projection_context.payload_for(&superseded_need).is_some();
    let output = ProjectionOutput::new()
        .need(recipient_need)
        .need(superseded_need);
    // 3. Materialize: offer local-recipient context or self-purge.
    if is_superseded {
        return Ok(output
            .row_mutation(RowMutation::DeleteWhere(TableDeleteWhere {
                table: LOCAL_RECIPIENT_KEY_ROWS,
                columns: &["workspace_id", "recipient_key_id"],
                values: vec![
                    Value::Bytes(local.workspace_id.to_vec()),
                    Value::Bytes(local.recipient_key_id.to_vec()),
                ],
            }))
            .purge_self(fact.id));
    }

    Ok(output
        .row_mutation(RowMutation::InsertValues(TableInsert {
            table: LOCAL_RECIPIENT_KEY_ROWS,
            columns: &[
                "workspace_id",
                "recipient_key_id",
                "fact_timestamp",
                "recipient_key",
                "recipient_secret",
            ],
            values: vec![
                Value::Bytes(local.workspace_id.to_vec()),
                Value::Bytes(local.recipient_key_id.to_vec()),
                Value::U64(fact.timestamp),
                Value::Bytes(local.recipient_key.to_vec()),
                Value::Bytes(local.recipient_secret.to_vec()),
            ],
        }))
        .offer(ContextOfferClaim::range(
            "local_recipient_key",
            scope,
            local.recipient_key_id,
            local.recipient_key_id,
        )))
}
