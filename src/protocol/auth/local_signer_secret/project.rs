pub mod decode {
    //! Byte decoding for local signer-secret facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, field order, and that the
    //! decoded material is canonical. Id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{validate, LOCAL_SIGNER_SECRET_BYTES, TYPE_LOCAL_SIGNER_SECRET};
    use super::super::fact::LocalSignerSecretFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<LocalSignerSecretFact, String> {
        wire::expect_len(bytes, LOCAL_SIGNER_SECRET_BYTES).map_err(wire_err)?;
        let actual = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if actual != TYPE_LOCAL_SIGNER_SECRET {
            return Err("expected local signer secret".to_string());
        }
        let fact = LocalSignerSecretFact {
            workspace_id: bytes[1..33].try_into().unwrap(),
            signer_id: bytes[33..65].try_into().unwrap(),
            public_key: bytes[65..97].try_into().unwrap(),
            private_key: bytes[97..129].try_into().unwrap(),
        };
        validate(&fact)?;
        Ok(fact)
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::core::crypto;
        use crate::protocol::auth::local_signer_secret::encode::{
            encode_fact, LOCAL_SIGNER_SECRET_BYTES,
        };

        fn sample_fact() -> LocalSignerSecretFact {
            let private_key = [9; 32];
            let public_key = crypto::ed25519_public_key(&private_key);
            LocalSignerSecretFact {
                workspace_id: [1; 32],
                signer_id: [2; 32],
                public_key,
                private_key,
            }
        }

        #[test]
        fn local_signer_secret_roundtrips_fixed_width() {
            let fact = sample_fact();

            let encoded = encode_fact(&fact).expect("encode local signer secret");

            assert_eq!(encoded.len(), LOCAL_SIGNER_SECRET_BYTES);
            assert_eq!(
                decode_fact(&encoded).expect("decode local signer secret"),
                fact
            );
        }
    }
}
pub mod authenticate {
    //! Local signer-secret authenticator.
    //!
    //! POLICY. Authenticating a `local_signer_secret` fact proves, over its bytes
    //! alone:
    //!   1. LAYOUT. The bytes decode to a canonical local signer-secret fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! These are local-only private signing material, never shareable signed
    //! envelopes, so there is no fact-boundary signature. Admission scope (`Local`)
    //! and publishing local signer context are interpretation the projector owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::LocalSignerSecretFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        secret: LocalSignerSecretFact,
        _context: &ProjectionContext,
    ) -> Result<LocalSignerSecretFact, String> {
        prove_decoded_local_signer_secret(fact, secret)
    }

    fn prove_decoded_local_signer_secret(
        fact: &Fact,
        secret: LocalSignerSecretFact,
    ) -> Result<LocalSignerSecretFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(secret)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::crypto;
        use crate::core::facts::{Fact, FactScope};
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::local_signer_secret::encode;
        use crate::protocol::auth::local_signer_secret::fact::LocalSignerSecretFact;

        fn canonical_fact() -> Fact {
            let private_key = [9; 32];
            let public_key = crypto::ed25519_public_key(&private_key);
            let secret = LocalSignerSecretFact {
                workspace_id: [1; 32],
                signer_id: [2; 32],
                public_key,
                private_key,
            };
            let bytes = encode::encode_fact(&secret).expect("encode local signer secret");
            Fact::new(FactScope::Local, 123, bytes)
        }

        fn authenticate(fact: &Fact) -> Result<LocalSignerSecretFact, String> {
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
    //! Local signer-secret semantic adapter.
    //!
    //! The current local_signer_secret wire shape is already the active semantic
    //! shape. This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::LocalSignerSecretFact;

    pub(crate) fn adapt(source: LocalSignerSecretFact) -> Result<LocalSignerSecretFact, String> {
        Ok(source)
    }
}

// Local signer-secret projector.
//
// POLICY. A local_signer_secret is admitted iff:
//   1. STRUCTURAL. The fact is local and decodes as validated private signing
//      material.
//   2. CONTEXT. It needs no remote context; local possession is the proof.
//   3. MATERIALIZE. It publishes local signer context under the workspace
//      scope and emits no rows, facts, intents, or shareable context.

use crate::core::facts::{Fact, FactScope, ScopeKind};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};

use super::fact::LocalSignerSecretFact;

/// Projector route metadata for the local_signer_secret fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::local_signer_secret::project::LocalSignerSecretProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct LocalSignerSecretProjector;

impl LocalSignerSecretProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for LocalSignerSecretProjector {
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

impl LocalSignerSecretProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        secret: LocalSignerSecretFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("local signer secret fact must have local scope".to_string());
        }

        // 2. Context.
        // Local possession is the context proof; no durable remote witness is
        // needed before publishing the local signer offer.

        // 3. Materialize.
        Ok(
            ProjectionOutput::new().offer(crate::core::context::ContextOffer::range(
                fact.id,
                "local_signer_secret",
                workspace_scope(secret.workspace_id),
                secret.signer_id,
                secret.signer_id,
            )),
        )
    }
}

fn workspace_scope(workspace_id: crate::core::facts::FactId) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    }
}
