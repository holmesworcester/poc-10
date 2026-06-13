pub mod decode {
    //! Byte decoding for local endpoint facts.
    //!
    //! Decoding re-derives both public keys from the private keys, so corrupted
    //! or mismatched identity facts fail before projection.

    use crate::core::crypto;
    use crate::core::wire;

    use super::super::encode::{FACT_BYTES, TYPE_LOCAL_ENDPOINT};
    use super::super::fact::EndpointFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<EndpointFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_LOCAL_ENDPOINT {
            return Err("expected local endpoint fact".to_string());
        }
        let mut endpoint = [0; 32];
        endpoint.copy_from_slice(&bytes[1..33]);
        let mut secret = [0; 32];
        secret.copy_from_slice(&bytes[33..65]);
        let mut signing_public_key = [0; 32];
        signing_public_key.copy_from_slice(&bytes[65..97]);
        let mut signing_secret = [0; 32];
        signing_secret.copy_from_slice(&bytes[97..129]);

        if crypto::x25519_public_key(&secret) != endpoint {
            return Err("local endpoint secret does not match endpoint".to_string());
        }
        if crypto::ed25519_public_key(&signing_secret) != signing_public_key {
            return Err(
                "local endpoint signing secret does not match signing public key".to_string(),
            );
        }
        Ok(EndpointFact {
            endpoint,
            secret,
            signing_public_key,
            signing_secret,
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::endpoint::encode::{encode_fact, FACT_BYTES};

        fn keypair() -> EndpointFact {
            let secret = [3u8; 32];
            let signing_secret = [5u8; 32];
            EndpointFact {
                endpoint: crypto::x25519_public_key(&secret),
                secret,
                signing_public_key: crypto::ed25519_public_key(&signing_secret),
                signing_secret,
            }
        }

        #[test]
        fn endpoint_fact_roundtrips() {
            let encoded = encode_fact(&keypair()).expect("encode");
            assert_eq!(encoded.len(), FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), keypair());
        }

        #[test]
        fn rejects_mismatched_endpoint() {
            let mut k = keypair();
            k.endpoint = [0; 32];
            let bytes = encode_fact(&k).expect("encode");
            assert_eq!(
                decode_fact(&bytes).expect_err("must reject"),
                "local endpoint secret does not match endpoint"
            );
        }

        #[test]
        fn rejects_mismatched_signing_public_key() {
            let mut k = keypair();
            k.signing_public_key = [0; 32];
            let bytes = encode_fact(&k).expect("encode");
            assert_eq!(
                decode_fact(&bytes).expect_err("must reject"),
                "local endpoint signing secret does not match signing public key"
            );
        }
    }
}
pub mod authenticate {
    //! Local-endpoint authenticator.
    //!
    //! POLICY. Authenticating a local `endpoint` fact proves, over its bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical endpoint fact — the layout
    //!      re-derives both public keys from the stored private keys.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! These are local identity secrets, not a signed shared proof, so there is no
    //! fact-boundary signature. Admission scope (`Local`) is interpretation the
    //! projector owns.

    use crate::core::facts::Fact;
    use crate::core::pipeline::{verify_fact_id, ProjectionContext};

    use super::super::fact::EndpointFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        endpoint: EndpointFact,
        _context: &ProjectionContext,
    ) -> Result<EndpointFact, String> {
        prove_decoded_endpoint(fact, endpoint)
    }

    fn prove_decoded_endpoint(fact: &Fact, endpoint: EndpointFact) -> Result<EndpointFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(endpoint)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::pipeline::ProjectionContext;
        use crate::protocol::auth::endpoint::author::{create_local_endpoint, endpoint_fact};
        use crate::protocol::auth::endpoint::fact::EndpointFact;

        fn canonical_fact() -> Fact {
            endpoint_fact(100, create_local_endpoint()).expect("endpoint fact")
        }

        fn authenticate(fact: &Fact) -> Result<EndpointFact, String> {
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
    //! Local-endpoint semantic adapter.
    //!
    //! The current endpoint wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::EndpointFact;

    pub(crate) fn adapt(source: EndpointFact) -> Result<EndpointFact, String> {
        Ok(source)
    }
}

// Poc-10 local endpoint projector.
//
// POLICY. A local endpoint fact is admitted iff:
//   1. STRUCTURAL. The fact is local-only and endpoint layout re-derives both
//      public keys from the stored private keys.
//   2. CONTEXT. No remote context is accepted; this is local identity secret
//      material.
//   3. MATERIALIZE. Write the four local endpoint rows for public/secret and
//      signing public/secret material, and publish local endpoint context keyed
//      by the endpoint id for bootstrap receive projection.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::pipeline::{FactPipeline, ProjectionContext, ProjectionOutput, Projector};

use super::endpoint_rows;

/// Projector route metadata for the endpoint fact.
pub const PIPELINE: FactPipeline =
    FactPipeline::projector("auth::endpoint::project::EndpointProjector");

const DAEMON_ENDPOINT_ROLE: &str = "auth_daemon_endpoint";
const DAEMON_ENDPOINT_KEY: &[u8] = b"daemon_endpoint";

pub fn daemon_endpoint_need(
    owner: crate::core::facts::FactId,
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        DAEMON_ENDPOINT_ROLE,
        crate::core::facts::FactScope::Local,
        DAEMON_ENDPOINT_KEY,
        DAEMON_ENDPOINT_KEY,
    )
}

pub fn daemon_endpoint_offer(
    owner: crate::core::facts::FactId,
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        DAEMON_ENDPOINT_ROLE,
        crate::core::facts::FactScope::Local,
        DAEMON_ENDPOINT_KEY,
        DAEMON_ENDPOINT_KEY,
    )
}

#[derive(Debug, Clone, Default)]
pub struct EndpointProjector;

impl EndpointProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for EndpointProjector {
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

impl EndpointProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        endpoint: super::fact::EndpointFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("local endpoint fact must have local scope".to_string());
        }

        // 3. Materialize.
        let mut output = ProjectionOutput::new();
        output = output.offer(crate::core::context::ContextOffer::range(
            fact.id,
            "auth_local_endpoint",
            crate::core::facts::FactScope::Local,
            endpoint.endpoint,
            endpoint.endpoint,
        ));
        output = output.offer(daemon_endpoint_offer(fact.id));
        for row in endpoint_rows(&endpoint) {
            output = output.row_mutation(RowMutation::PutRow(row));
        }
        Ok(output)
    }
}
