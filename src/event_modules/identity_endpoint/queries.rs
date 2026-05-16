//! Read-only local endpoint lookups.
//!
//! Commands may create the local endpoint, but reactive handlers only need to
//! load and validate existing local capability rows. Keeping that lookup here
//! lets handlers stay out of user-facing `commands.rs`.

use crate::core::crypto;
use crate::core::store::Store;

use super::fact::EndpointFact;
use super::rows;

pub fn local_endpoint(store: &Store) -> Result<Option<EndpointFact>, String> {
    let endpoint = store
        .table_row(rows::LOCAL_ENDPOINT_ROWS, rows::LOCAL_KEY)
        .map_err(|err| format!("load local endpoint: {err}"))?;
    let secret = store
        .table_row(rows::LOCAL_ENDPOINT_SECRET_ROWS, rows::LOCAL_KEY)
        .map_err(|err| format!("load local endpoint secret: {err}"))?;
    let signing_public_key = store
        .table_row(
            rows::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
            rows::LOCAL_KEY,
        )
        .map_err(|err| format!("load local endpoint signing public key: {err}"))?;
    let signing_secret = store
        .table_row(rows::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS, rows::LOCAL_KEY)
        .map_err(|err| format!("load local endpoint signing secret: {err}"))?;

    match (endpoint, secret, signing_public_key, signing_secret) {
        (None, None, None, None) => Ok(None),
        (Some(endpoint), Some(secret), Some(signing_public_key), Some(signing_secret)) => {
            let endpoint = id32(&endpoint, "local endpoint")?;
            let secret = id32(&secret, "local endpoint secret")?;
            let signing_public_key =
                id32(&signing_public_key, "local endpoint signing public key")?;
            let signing_secret = id32(&signing_secret, "local endpoint signing secret")?;
            if crypto::x25519_public_key(&secret) != endpoint {
                return Err("stored endpoint does not match local endpoint secret".to_string());
            }
            if crypto::ed25519_public_key(&signing_secret) != signing_public_key {
                return Err(
                    "stored endpoint signing key does not match local signing secret".to_string(),
                );
            }
            Ok(Some(EndpointFact {
                endpoint,
                secret,
                signing_public_key,
                signing_secret,
            }))
        }
        (None, _, _, _) => Err("local endpoint public key is missing".to_string()),
        (_, None, _, _) => Err("local endpoint secret is missing".to_string()),
        (_, _, None, _) => Err("local endpoint signing public key is missing".to_string()),
        (_, _, _, None) => Err("local endpoint signing secret is missing".to_string()),
    }
}

fn id32(value: &[u8], label: &str) -> Result<[u8; 32], String> {
    value
        .try_into()
        .map_err(|_| format!("{label} row must be 32 bytes"))
}
