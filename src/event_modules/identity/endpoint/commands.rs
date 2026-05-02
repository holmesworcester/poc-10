use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::store::{CommandOutput, StateChanges};

use super::projector;
use super::types::EndpointKeypair;

pub fn create_local_keypair() -> CommandOutput<EndpointKeypair> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let endpoint = PublicKey::from(&secret).to_bytes();
    let secret = secret.to_bytes();
    CommandOutput::with_changes(
        EndpointKeypair { endpoint, secret },
        StateChanges::rows(projector::local_endpoint(endpoint, secret)),
    )
}
