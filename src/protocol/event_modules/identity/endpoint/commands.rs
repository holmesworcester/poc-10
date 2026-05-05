//! Command for creating the local endpoint.
//!
//! The create command returns the generated keypair and proposes the local
//! endpoint event that will store it. The read helper below is intentionally
//! expressed against a narrow context trait rather than `Store`; callers decide
//! where the data comes from, and this module owns the keypair consistency
//! check.

use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::{EndpointId, EndpointKeypair};

pub trait LocalEndpointRead {
    fn local_endpoint_secret(&self) -> Result<Option<Vec<u8>>, String>;
    fn local_endpoint(&self) -> Result<Option<Vec<u8>>, String>;
}

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

pub fn local_or_create(
    context: &impl LocalEndpointRead,
) -> Result<CommandOutput<EndpointKeypair>, String> {
    match local_keypair(context)? {
        Some(local) => Ok(CommandOutput::new(local)),
        None => Ok(create_local_keypair()),
    }
}

pub fn local_keypair(context: &impl LocalEndpointRead) -> Result<Option<EndpointKeypair>, String> {
    let secret = context.local_endpoint_secret()?;
    let endpoint = context.local_endpoint()?;

    match (secret, endpoint) {
        (Some(secret), Some(endpoint)) => {
            let secret = endpoint_id(&secret)?;
            let endpoint = endpoint_id(&endpoint)?;
            let derived = PublicKey::from(&StaticSecret::from(secret)).to_bytes();
            if derived != endpoint {
                return Err("stored endpoint does not match local endpoint secret".to_string());
            }
            Ok(Some(EndpointKeypair { endpoint, secret }))
        }
        (None, None) => Ok(None),
        (None, Some(_)) => Err("local endpoint secret is missing".to_string()),
        (Some(_), None) => Err("local endpoint public key is missing".to_string()),
    }
}

fn endpoint_id(bytes: &[u8]) -> Result<EndpointId, String> {
    if bytes.len() != 32 {
        return Err("stored endpoint id is malformed".to_string());
    }
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}
