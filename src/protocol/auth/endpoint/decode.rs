//! Byte decoding for local endpoint facts.
//!
//! Decoding re-derives both public keys from the private keys, so corrupted
//! or mismatched identity facts fail before projection.

use crate::core::crypto;
use crate::core::wire;

use super::encode::{FACT_BYTES, TYPE_LOCAL_ENDPOINT};
use super::fact::EndpointFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = EndpointFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

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
        return Err("local endpoint signing secret does not match signing public key".to_string());
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
