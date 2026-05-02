use x25519_dalek::{PublicKey, StaticSecret};

use crate::store::Store;

use super::tables;
use super::types::{EndpointId, EndpointKeypair};

pub fn local_keypair(store: &Store) -> Result<Option<EndpointKeypair>, String> {
    let secret = store
        .table_row(tables::LOCAL_ENDPOINT_SECRET, b"local")
        .map_err(|err| format!("load local endpoint secret: {err}"))?;
    let endpoint = store
        .table_row(tables::LOCAL_ENDPOINT, b"local")
        .map_err(|err| format!("load local endpoint: {err}"))?;

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

pub fn endpoint_id(bytes: &[u8]) -> Result<EndpointId, String> {
    if bytes.len() != 32 {
        return Err("stored endpoint id is malformed".to_string());
    }
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}
