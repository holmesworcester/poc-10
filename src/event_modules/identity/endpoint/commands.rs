use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::store::Store;

use super::types::{EndpointId, EndpointKeypair};
use super::{projector, tables};

pub fn ensure_local_keypair(store: &Store) -> Result<EndpointKeypair, String> {
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
            Ok(EndpointKeypair { endpoint, secret })
        }
        (None, None) => {
            let secret = StaticSecret::random_from_rng(OsRng);
            let endpoint = PublicKey::from(&secret).to_bytes();
            let secret = secret.to_bytes();
            store
                .insert_table_rows(projector::local_endpoint(endpoint, secret))
                .map_err(|err| format!("store local endpoint: {err}"))?;
            Ok(EndpointKeypair { endpoint, secret })
        }
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
