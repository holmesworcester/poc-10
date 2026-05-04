//! Command for creating the local endpoint.
//!
//! The command returns the generated keypair and proposes the local endpoint
//! event that will store it. It does not inspect or mutate existing state; the
//! protocol facade decides whether creation is needed before calling it.

use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol::event_modules::worker::CommandOutput;

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
