pub mod decode {
    //! Byte decoding for local key-wrap creation facts.

    use crate::core::wire;
    use crate::protocol::auth::key_wrap::fact::WrapSourceKind;

    use super::super::encode::{validate_fact, KEY_WRAP_CREATION_BYTES, TYPE_KEY_WRAP_CREATION};
    use super::super::fact::KeyWrapCreationFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<KeyWrapCreationFact, String> {
        wire::expect_len(bytes, KEY_WRAP_CREATION_BYTES).map_err(wire_err)?;
        if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_KEY_WRAP_CREATION {
            return Err("expected key wrap creation".to_string());
        }
        let source = match bytes[201] {
            1 => {
                if bytes[202..252].iter().any(|byte| *byte != 0) {
                    return Err("invalid key wrap creation root padding".to_string());
                }
                WrapSourceKind::FrontierRoot
            }
            2 => WrapSourceKind::HistoryNode {
                range_start: wire::take_u64be(&bytes[202..210]).map_err(wire_err)?,
                range_width: wire::take_u64be(&bytes[210..218]).map_err(wire_err)?,
                bit_depth: wire::take_u16be(&bytes[218..220]).map_err(wire_err)?,
                fact_id_prefix: bytes[220..252].try_into().unwrap(),
            },
            _ => return Err("invalid key wrap creation source kind".to_string()),
        };
        let fact = KeyWrapCreationFact {
            workspace_id: bytes[1..33].try_into().unwrap(),
            frontier_id: bytes[33..65].try_into().unwrap(),
            recipient_key_id: bytes[65..97].try_into().unwrap(),
            source_fact_id: bytes[97..129].try_into().unwrap(),
            signer_secret_fact_id: bytes[129..161].try_into().unwrap(),
            owner_endpoint_id: bytes[161..193].try_into().unwrap(),
            frontier_created_at_ms: wire::take_u64be(&bytes[193..201]).map_err(wire_err)?,
            source,
        };
        validate_fact(&fact)?;
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
        use crate::protocol::auth::key_wrap_creation::encode::{
            encode_fact, KEY_WRAP_CREATION_BYTES,
        };

        fn sample_fact() -> KeyWrapCreationFact {
            KeyWrapCreationFact {
                workspace_id: [1; 32],
                frontier_id: [2; 32],
                recipient_key_id: [3; 32],
                source_fact_id: [4; 32],
                signer_secret_fact_id: [5; 32],
                owner_endpoint_id: [6; 32],
                frontier_created_at_ms: 123,
                source: WrapSourceKind::FrontierRoot,
            }
        }

        #[test]
        fn key_wrap_creation_roundtrips_fixed_width() {
            let fact = sample_fact();

            let encoded = encode_fact(&fact).expect("encode key wrap creation");

            assert_eq!(encoded.len(), KEY_WRAP_CREATION_BYTES);
            assert_eq!(
                decode_fact(&encoded).expect("decode key wrap creation"),
                fact
            );
        }
    }
}

pub mod authenticate {
    //! Local key-wrap creation authenticator.
    //!
    //! POLICY. Authenticating a `key_wrap_creation` fact proves canonical local
    //! bytes and content id. Projection owns the context proof that the named
    //! recipient, source, and signer facts match.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::KeyWrapCreationFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        creation: KeyWrapCreationFact,
        _context: &ProjectionContext,
    ) -> Result<KeyWrapCreationFact, String> {
        verify_fact_id(fact)?;
        Ok(creation)
    }
}

pub mod adapt {
    //! Key-wrap creation semantic adapter.

    use super::super::fact::KeyWrapCreationFact;

    pub(crate) fn adapt(source: KeyWrapCreationFact) -> Result<KeyWrapCreationFact, String> {
        Ok(source)
    }
}

// Local key-wrap creation projector.
//
// POLICY. A key-wrap creation fact is admitted only locally. Projection waits
// for the exact recipient key, source secret, and signer secret context it
// names, then emits the deterministic shared key-wrap fact and its detached
// signer proof.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::key_wrap::create_validated_key_wrap_facts;
use crate::protocol::auth::key_wrap::project::{matched_payload_fact, require_local_scope};

use super::fact::KeyWrapCreationFact;

pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::key_wrap_creation::project::KeyWrapCreationProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct KeyWrapCreationProjector;

impl KeyWrapCreationProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for KeyWrapCreationProjector {
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

impl KeyWrapCreationProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        creation: KeyWrapCreationFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_key_wrap_creation(fact, context, creation)
    }
}

fn project_key_wrap_creation(
    fact: &Fact,
    projection_context: &ProjectionContext,
    creation: KeyWrapCreationFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    require_local_scope(fact)?;
    let scope = crate::protocol::auth::workspace::scope(creation.workspace_id);

    // 2. Context: exact recipient, source, and signer facts named by this work fact.
    let recipient_need = ContextNeed::for_key(
        fact.id,
        "recipient_key",
        scope.clone(),
        creation.recipient_key_id,
    );
    let source_need = ContextNeed::for_key(
        fact.id,
        "local_secret_source",
        FactScope::Local,
        creation.source_fact_id,
    );
    let signer_need = ContextNeed::for_key(
        fact.id,
        "local_signer_secret",
        scope,
        creation.owner_endpoint_id,
    );
    let output = ProjectionOutput::new()
        .need(recipient_need.clone())
        .need(source_need.clone())
        .need(signer_need.clone());
    let Some(recipient_fact) = matched_payload_fact(projection_context, &recipient_need) else {
        return Ok(output);
    };
    let Some(source_fact) = matched_payload_fact(projection_context, &source_need) else {
        return Ok(output);
    };
    let Some(signer_secret_fact) =
        matching_signer_secret_fact(projection_context, &signer_need, &creation)
    else {
        return Ok(output);
    };
    // 3. Materialize: deterministic shared key-wrap fact plus signer proof.
    let [key_wrap_fact, signature_fact] = create_validated_key_wrap_facts(
        &creation,
        recipient_fact,
        source_fact,
        signer_secret_fact,
    )?;
    Ok(output.fact(key_wrap_fact).fact(signature_fact))
}

fn matching_signer_secret_fact<'a>(
    projection_context: &'a ProjectionContext,
    need: &'a ContextNeed,
    creation: &KeyWrapCreationFact,
) -> Option<&'a Fact> {
    projection_context
        .matched_payloads_for(need)
        .map(|(_, payload)| payload)
        .find(|payload| payload.id == creation.signer_secret_fact_id)
}

// Tests.
//
// Invariants:
// - key_wrap_creation is local work and must never be admitted as synced
//   protocol evidence;
// - projection waits on the exact recipient key, local source secret, and local
//   signer secret named by the work fact;
// - before all three dependencies exist, projection emits no child key-wrap
//   fact.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::project_fact::Projector;
    use crate::protocol::auth::key_wrap::fact::WrapSourceKind;

    #[test]
    fn key_wrap_creation_waits_for_exact_recipient_source_and_signer_context() {
        let fact = local_creation_fact(sample_creation());
        let creation = decode::decode_fact(fact.body()).expect("decode creation");

        let output = KeyWrapCreationProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project without context");

        assert!(output.effects.facts.is_empty());
        assert_eq!(output.needs.len(), 3);
        assert!(output.needs.contains(&ContextNeed::for_key(
            fact.id,
            "recipient_key",
            crate::protocol::auth::workspace::scope(creation.workspace_id),
            creation.recipient_key_id
        )));
        assert!(output.needs.contains(&ContextNeed::for_key(
            fact.id,
            "local_secret_source",
            FactScope::Local,
            creation.source_fact_id
        )));
        assert!(output.needs.contains(&ContextNeed::for_key(
            fact.id,
            "local_signer_secret",
            crate::protocol::auth::workspace::scope(creation.workspace_id),
            creation.owner_endpoint_id
        )));
    }

    #[test]
    fn key_wrap_creation_projection_rejects_non_local_scope() {
        let creation = sample_creation();
        let non_local = Fact::new(
            crate::protocol::auth::workspace::scope(creation.workspace_id),
            10,
            super::super::encode::encode_fact(&creation).expect("encode creation"),
        );

        let err = KeyWrapCreationProjector::new()
            .project(&non_local, &ProjectionContext::default())
            .expect_err("non-local creation should reject");

        assert!(err.contains("local scope"), "{err}");
    }

    fn sample_creation() -> KeyWrapCreationFact {
        KeyWrapCreationFact {
            workspace_id: [1; 32],
            frontier_id: [2; 32],
            recipient_key_id: [3; 32],
            source_fact_id: [4; 32],
            signer_secret_fact_id: [5; 32],
            owner_endpoint_id: [6; 32],
            frontier_created_at_ms: 123,
            source: WrapSourceKind::FrontierRoot,
        }
    }

    fn local_creation_fact(creation: KeyWrapCreationFact) -> Fact {
        Fact::new(
            FactScope::Local,
            10,
            super::super::encode::encode_fact(&creation).expect("encode creation"),
        )
    }
}
