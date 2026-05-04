use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::core::store::CommandOutput;

use super::codec;
use super::types::EndpointKeypair;

pub fn create_local_keypair() -> CommandOutput<EndpointKeypair> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let endpoint = PublicKey::from(&secret).to_bytes();
    let secret = secret.to_bytes();
    let event = EndpointKeypair { endpoint, secret };
    let bytes = codec::encode(&event);
    CommandOutput::with_events(
        event,
        vec![codec::record_from_bytes(bytes).expect("encoded local endpoint is valid")],
    )
}
