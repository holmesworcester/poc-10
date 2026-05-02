//! Minimum legacy-shape identity surface kept around the substrate cutover.
//!
//! The new TCP substrate (`runtime/transport_v2`) does not use TLS, QUIC, or
//! certificates at the wire level. Endpoint identity on the wire is just a
//! 32-byte `EndpointId` — the BLAKE2b-256 hash of the peer's Ed25519 SubjectPublicKeyInfo.
//!
//! However, the projection pipeline still stores `(cert_der, key_der)` rows
//! in `local_transport_creds` and `daemon_identity` — that's a DB-shape
//! holdover from the old QUIC path. Until the projection schema migrates to
//! "store the keypair only", we need a small shim that:
//!
//! - generates a self-signed cert from an Ed25519 signing key (deterministic
//!   bootstrap / peershared identity),
//! - extracts the SPKI fingerprint from a cert (round-trip with the above),
//! - reads/writes the daemon's own endpoint identity row,
//! - implements `TransportIdentityMaterializer` so the projection `write_exec`
//!   can install bootstrap and peershared identities.
//!
//! Nothing in `runtime/transport_v2`, `runtime/control_loop`, or `runtime/jobs`
//! depends on this module. The substrate is byte-pipe-only.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use rand::rngs::OsRng;
use rcgen::{generate_simple_self_signed, Certificate, CertificateParams, KeyPair, PKCS_ED25519};
use rusqlite::{Connection, OptionalExtension};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use x509_parser::prelude::*;

use crate::contracts::transport_identity_contract::{
    TransportIdentityError, TransportIdentityMaterializer, TransportIdentitySpec,
};
use crate::db::transport_creds::{
    load_local_creds, peer_has_creds_with_source, store_local_creds_with_source,
    CRED_SOURCE_BOOTSTRAP, CRED_SOURCE_PEER_SHARED,
};

/// Generate a self-signed certificate with a fresh keypair.
pub fn generate_self_signed_cert() -> Result<
    (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let _ = OsRng;
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names)?;
    let cert_der = CertificateDer::from(cert.serialize_der()?);
    let key_der = PrivatePkcs8KeyDer::from(cert.serialize_private_key_der());
    Ok((cert_der, key_der))
}

/// Generate a deterministic self-signed Ed25519 certificate from an existing
/// signing key.
pub fn generate_self_signed_cert_from_signing_key(
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<
    (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let pkcs8 = signing_key.to_pkcs8_der()?;
    let key_bytes = pkcs8.as_bytes().to_vec();

    let key_pair = KeyPair::from_der(&key_bytes)
        .map_err(|e| format!("failed to parse signing key as PKCS#8: {}", e))?;

    let mut params = CertificateParams::new(vec!["localhost".to_string()]);
    params.alg = &PKCS_ED25519;
    params.key_pair = Some(key_pair);

    let cert = Certificate::from_params(params)
        .map_err(|e| format!("failed to build deterministic certificate params: {}", e))?;
    let cert_der = CertificateDer::from(cert.serialize_der()?);
    let key_der = PrivatePkcs8KeyDer::from(key_bytes);

    Ok((cert_der, key_der))
}

/// Extract SPKI from a DER-encoded certificate and hash it with BLAKE2b-256.
pub fn extract_spki_fingerprint(
    cert_der: &[u8],
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("failed to parse X.509 certificate: {}", e))?;
    let spki_bytes = cert.public_key().raw;
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(spki_bytes);
    let result = hasher.finalize();
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&result);
    Ok(fingerprint)
}

/// Load or create the daemon-level endpoint identity. Returns
/// `(peer_id_hex, cert_der, key_der)` where `peer_id_hex` is the 64-char
/// hex of the SPKI fingerprint that the new TCP substrate uses as its
/// `EndpointId`.
pub fn ensure_daemon_identity(
    conn: &Connection,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    if let Some(row) = crate::db::daemon_identity::load(conn)? {
        return Ok((
            row.peer_id,
            CertificateDer::from(row.cert_der),
            PrivatePkcs8KeyDer::from(row.key_der),
        ));
    }

    let (cert_der, key_der) = generate_self_signed_cert()?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    let peer_id = hex::encode(fp);
    crate::db::daemon_identity::store(
        conn,
        &peer_id,
        cert_der.as_ref(),
        key_der.secret_pkcs8_der().as_ref(),
    )?;
    Ok((peer_id, cert_der, key_der))
}

/// `db_path` convenience wrapper around [`ensure_daemon_identity`].
pub fn ensure_daemon_identity_from_db(
    db_path: &str,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    ensure_daemon_identity(&conn)
}

/// Install a deterministic transport identity derived from an invite signing
/// key. Used by the projection pipeline when an invite is accepted.
pub fn install_invite_bootstrap_transport_identity(
    conn: &Connection,
    invite_signing_key: &ed25519_dalek::SigningKey,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_der, key_der) = generate_self_signed_cert_from_signing_key(invite_signing_key)?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    let peer_id = hex::encode(fp);
    if peer_has_creds_with_source(conn, &peer_id, CRED_SOURCE_PEER_SHARED)? {
        return Err(
            "bootstrap transport identity install denied: peershared identity already installed for this peer"
                .into(),
        );
    }
    store_local_creds_with_source(
        conn,
        &peer_id,
        cert_der.as_ref(),
        key_der.secret_pkcs8_der(),
        CRED_SOURCE_BOOTSTRAP,
    )?;
    Ok(peer_id)
}

/// Install a deterministic transport identity derived from a peer-shared
/// signing key. Used by the projection pipeline when a peer becomes valid
/// for this tenant.
pub fn install_peer_key_transport_identity(
    conn: &Connection,
    peer_signing_key: &ed25519_dalek::SigningKey,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_der, key_der) = generate_self_signed_cert_from_signing_key(peer_signing_key)?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    let peer_id = hex::encode(fp);
    store_local_creds_with_source(
        conn,
        &peer_id,
        cert_der.as_ref(),
        key_der.secret_pkcs8_der(),
        CRED_SOURCE_PEER_SHARED,
    )?;
    Ok(peer_id)
}

/// Load existing transport credentials for a specific `peer_id`. Returns
/// `(cert_der, key_der)` or an error if no row exists.
pub fn load_transport_cert(
    conn: &Connection,
    peer_id: &str,
) -> Result<
    (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    match load_local_creds(conn, peer_id)? {
        Some((cert_bytes, key_bytes)) => {
            let cert_der = CertificateDer::from(cert_bytes);
            let key_der = PrivatePkcs8KeyDer::from(key_bytes);
            Ok((cert_der, key_der))
        }
        None => Err(format!("No transport credentials found for peer_id {}", peer_id).into()),
    }
}

/// Production materializer backed by the install_* functions above.
pub struct ConcreteTransportIdentityMaterializer;

fn parse_signing_key(
    key_bytes: Vec<u8>,
) -> Result<ed25519_dalek::SigningKey, TransportIdentityError> {
    if key_bytes.len() != 32 {
        return Err(TransportIdentityError::InvalidKeyMaterial(format!(
            "expected 32 bytes, got {}",
            key_bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
}

impl TransportIdentityMaterializer for ConcreteTransportIdentityMaterializer {
    fn materialize(
        &self,
        conn: &Connection,
        spec: TransportIdentitySpec,
    ) -> Result<String, TransportIdentityError> {
        match spec {
            TransportIdentitySpec::InstallBootstrapIdentityFromInviteSecret {
                invite_event_id,
            } => {
                let invite_eid_b64 = crate::crypto::event_id_to_base64(&invite_event_id);
                // `invite_event_id` is globally unique (it's the invite
                // event's own id), so the lookup is keyed on it alone.
                let key_bytes: Option<Vec<u8>> = conn
                    .query_row(
                        "SELECT private_key FROM invite_secrets
                         WHERE invite_event_id = ?1
                         ORDER BY created_at DESC, event_id DESC
                         LIMIT 1",
                        rusqlite::params![invite_eid_b64],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|e| TransportIdentityError::InstallFailed(e.to_string()))?
                    .flatten();

                let key_bytes =
                    key_bytes.ok_or_else(|| TransportIdentityError::InviteSecretNotFound {
                        invite_event_id: invite_eid_b64.clone(),
                    })?;
                let signing_key = parse_signing_key(key_bytes)?;
                let peer_id = install_invite_bootstrap_transport_identity(conn, &signing_key)
                    .map_err(|e| TransportIdentityError::InstallFailed(e.to_string()))?;
                Ok(peer_id)
            }
            TransportIdentitySpec::InstallPeerSharedIdentityFromSigner { signer_event_id } => {
                let signer_eid_b64 = crate::crypto::event_id_to_base64(&signer_event_id);
                let key_bytes: Option<Vec<u8>> = conn
                    .query_row(
                        "SELECT private_key FROM peer_secrets
                         WHERE signer_event_id = ?1
                         ORDER BY created_at DESC, secret_event_id DESC
                         LIMIT 1",
                        rusqlite::params![signer_eid_b64],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|e| TransportIdentityError::InstallFailed(e.to_string()))?
                    .flatten();

                let key_bytes =
                    key_bytes.ok_or_else(|| TransportIdentityError::SignerKeyNotFound {
                        signer_event_id: signer_eid_b64.clone(),
                    })?;

                let signing_key = parse_signing_key(key_bytes)?;
                let peer_id = install_peer_key_transport_identity(conn, &signing_key)
                    .map_err(|e| TransportIdentityError::InstallFailed(e.to_string()))?;
                Ok(peer_id)
            }
        }
    }
}
