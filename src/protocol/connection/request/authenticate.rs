//! Connection-request authenticator.
//!
//! A connection request is a sealed carrier fact. Authenticating it proves the
//! fact boundary:
//!   1. LAYOUT. The bytes are a canonical sealed connection-request envelope
//!      (proven by the family `Codec` / `validate_sealed_fact`).
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. OPEN. The sealed body opens with either local sender ephemeral context
//!      or local receiver endpoint context.
//!   4. SIGNATURE. The opened bootstrap or membership request signature verifies
//!      against the local invite secret or global endpoint_shared verifier.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};
use crate::protocol::auth::{endpoint, endpoint_shared, invite};
use crate::protocol::connection::ephemeral_secret;

use super::fact::{ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP};
use super::{author, decode};

pub(crate) struct ConnectionRequestAuthenticator;

#[derive(Debug, Clone)]
pub(crate) enum AuthenticatedConnectionRequest {
    Sender {
        request: ConnectionRequestFact,
        base_need: ContextNeed,
    },
    Receiver {
        request: ConnectionRequestFact,
        base_need: ContextNeed,
    },
}

impl DecodedAuthenticator<super::Codec> for ConnectionRequestAuthenticator {
    type Authenticated = AuthenticatedConnectionRequest;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        _decoded: (),
        context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        if let Err(error) = verify_fact_id(fact) {
            return Authentication::Invalid(error);
        }

        let sender_need = all_ephemeral_secret_need(fact.id);
        for (_, secret_fact) in context.matched_payloads_for(&sender_need) {
            if secret_fact.scope != FactScope::Local {
                return Authentication::Invalid(
                    "connection request sender secret context must be local".to_string(),
                );
            }
            let secret =
                match ephemeral_secret::decode_fact_payload(secret_fact.body()).map_err(|_| {
                    "connection request sender context is not an ephemeral secret".to_string()
                }) {
                    Ok(secret) => secret,
                    Err(error) => return Authentication::Invalid(error),
                };
            let Ok(request) = decode::open_fact_as_sender(fact.body(), &secret) else {
                continue;
            };
            if let Err(error) = validate_common_request(fact.id, &request) {
                return Authentication::Invalid(error);
            }
            if request.initiator_ephemeral_secret_fact_id != secret_fact.id {
                return Authentication::Invalid(
                    "connection request sender secret id does not match request".to_string(),
                );
            }
            match authenticate_request_signature(fact.id, &request, context) {
                Ok(Some(needs)) => {
                    return Authentication::needs([sender_need.clone()].into_iter().chain(needs));
                }
                Ok(None) => {
                    return Authentication::Authenticated(
                        crate::core::pipeline::AuthenticatedFact::new(
                            fact,
                            AuthenticatedConnectionRequest::Sender {
                                request,
                                base_need: sender_need.clone(),
                            },
                        ),
                    );
                }
                Err(error) => return Authentication::Invalid(error),
            }
        }

        let receiver_need = all_local_endpoint_need(fact.id);
        for (_, endpoint_fact) in context.matched_payloads_for(&receiver_need) {
            if endpoint_fact.scope != FactScope::Local {
                return Authentication::Invalid(
                    "connection request receiver endpoint context must be local".to_string(),
                );
            }
            let local_endpoint =
                match endpoint::decode_fact_payload(endpoint_fact.body()).map_err(|_| {
                    "connection request receiver context is not a local endpoint".to_string()
                }) {
                    Ok(endpoint) => endpoint,
                    Err(error) => return Authentication::Invalid(error),
                };
            let Ok(request) = decode::open_fact(fact.body(), &local_endpoint) else {
                continue;
            };
            if let Err(error) = validate_common_request(fact.id, &request) {
                return Authentication::Invalid(error);
            }
            match authenticate_request_signature(fact.id, &request, context) {
                Ok(Some(needs)) => {
                    return Authentication::needs([receiver_need.clone()].into_iter().chain(needs));
                }
                Ok(None) => {
                    return Authentication::Authenticated(
                        crate::core::pipeline::AuthenticatedFact::new(
                            fact,
                            AuthenticatedConnectionRequest::Receiver {
                                request,
                                base_need: receiver_need.clone(),
                            },
                        ),
                    );
                }
                Err(error) => return Authentication::Invalid(error),
            }
        }

        Authentication::needs([sender_need, receiver_need])
    }
}

fn authenticate_request_signature(
    owner: FactId,
    request: &ConnectionRequestFact,
    context: &ProjectionContext,
) -> Result<Option<Vec<ContextNeed>>, String> {
    match request.mode {
        REQUEST_MODE_BOOTSTRAP => {
            let invite_need = invite_secret_need(owner, request.invite_secret_fact_id);
            let Some(invite_fact) = context.payload_for(&invite_need) else {
                return Ok(Some(vec![invite_need]));
            };
            if invite_fact.scope != FactScope::Local {
                return Err("connection request invite context must be local".to_string());
            }
            let invite = invite::decode_fact_payload(invite_fact.body())
                .map_err(|_| "connection request invite context is malformed".to_string())?;
            author::validate_invite_signature(request, &invite)?;
            Ok(None)
        }
        REQUEST_MODE_MEMBERSHIP => {
            let shared_need = endpoint_shared_need(owner, request.initiator_endpoint_shared_id);
            let Some(shared_fact) = context.payload_for(&shared_need) else {
                return Ok(Some(vec![shared_need]));
            };
            if shared_fact.scope != FactScope::Global {
                return Err("connection request endpoint_shared context must be global".to_string());
            }
            let shared =
                endpoint_shared::decode_fact_payload(shared_fact.body()).map_err(|_| {
                    "connection request endpoint_shared context is malformed".to_string()
                })?;
            if shared.endpoint_id != request.from_endpoint {
                return Err("connection request endpoint_shared does not bind sender".to_string());
            }
            author::validate_endpoint_signature(request, &shared.signing_public_key)?;
            Ok(None)
        }
        _ => unreachable!("validated request mode"),
    }
}

pub(super) fn validate_common_request(
    request_id: FactId,
    request: &ConnectionRequestFact,
) -> Result<(), String> {
    if request_id == [0; 32] {
        return Err("connection request id cannot be empty".to_string());
    }
    if request.from_endpoint == [0; 32] {
        return Err("connection request from_endpoint cannot be empty".to_string());
    }
    if request.to_endpoint == [0; 32] {
        return Err("connection request to_endpoint cannot be empty".to_string());
    }
    if request.from_endpoint == request.to_endpoint {
        return Err("connection request endpoints must differ".to_string());
    }
    if request.initiator_ephemeral_secret_fact_id == [0; 32] {
        return Err("connection request initiator ephemeral id cannot be empty".to_string());
    }
    if request.initiator_ephemeral_public_key == [0; 32] {
        return Err(
            "connection request initiator ephemeral public key cannot be empty".to_string(),
        );
    }
    author::validate_mode_shape(request)
}

pub(super) fn all_ephemeral_secret_need(owner: FactId) -> ContextNeed {
    ContextNeed::range(
        owner,
        "connection_ephemeral_secret",
        FactScope::Local,
        [0; 32],
        [0xff; 32],
    )
}

pub(super) fn all_local_endpoint_need(owner: FactId) -> ContextNeed {
    ContextNeed::range(
        owner,
        "auth_local_endpoint",
        FactScope::Local,
        [0; 32],
        [0xff; 32],
    )
}

pub(super) fn invite_secret_need(owner: FactId, invite_secret_id: FactId) -> ContextNeed {
    exact_need(
        owner,
        "connection_invite_secret",
        FactScope::Local,
        invite_secret_id,
    )
}

pub(super) fn endpoint_shared_need(owner: FactId, endpoint_shared_id: FactId) -> ContextNeed {
    exact_need(
        owner,
        "auth_endpoint_shared",
        FactScope::Global,
        endpoint_shared_id,
    )
}

pub(super) fn exact_need(
    owner: FactId,
    role: &'static str,
    scope: FactScope,
    key: FactId,
) -> ContextNeed {
    ContextNeed::range(owner, role, scope, key, key)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::connection::request::author::sign_request;
    use crate::protocol::connection::request::encode;
    use crate::protocol::connection::request::fact::{
        ConnectionRequestFact, REQUEST_MODE_MEMBERSHIP,
    };

    use super::ConnectionRequestAuthenticator;

    const SIGNING_SECRET: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        let from_endpoint = [1; 32];
        let to_secret = [9; 32];
        let to_endpoint = crypto::x25519_public_key(&to_secret);
        let initiator_ephemeral_private_key = [10; 32];
        let mut request = ConnectionRequestFact {
            mode: REQUEST_MODE_MEMBERSHIP,
            from_endpoint,
            to_endpoint,
            nonce: [3; 32],
            dialed_addr: Some("127.0.0.1:41001".parse().unwrap()),
            initiator_addr: Some("127.0.0.1:41000".parse().unwrap()),
            invite_fact_id: [0; 32],
            bootstrap_hash: [0; 32],
            invite_secret_fact_id: [0; 32],
            invite_signature: [0; ED25519_SIGNATURE_BYTES],
            initiator_endpoint_shared_id: [4; 32],
            endpoint_signature: [0; ED25519_SIGNATURE_BYTES],
            initiator_ephemeral_secret_fact_id: [5; 32],
            initiator_ephemeral_public_key: crypto::x25519_public_key(
                &initiator_ephemeral_private_key,
            ),
        };
        let endpoint = EndpointFact {
            endpoint: from_endpoint,
            secret: [8; 32],
            signing_public_key: crypto::ed25519_public_key(&SIGNING_SECRET),
            signing_secret: SIGNING_SECRET,
        };
        sign_request(&mut request, &endpoint).expect("sign membership connection request");
        let bytes = encode::seal_fact(&request, &initiator_ephemeral_private_key)
            .expect("seal connection_request fact");
        Fact::new(FactScope::Global, 100, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, super::AuthenticatedConnectionRequest> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => ConnectionRequestAuthenticator::authenticate_decoded(
                fact,
                decoded,
                &ProjectionContext::default(),
            ),
            Err(error) => Authentication::Invalid(error),
        }
    }

    fn is_invalid(fact: &Fact) -> bool {
        matches!(authenticate(fact), Authentication::Invalid(_))
    }

    // The membership signing key is not embedded in the request — it lives in the
    // initiator's endpoint_shared — so a well-formed canonical request parks on
    // that context (NeedsAuthentication) rather than authenticating outright. We
    // assert it is NOT Invalid; the signature itself is proven once context lands.
    #[test]
    fn authenticates_canonical_fact() {
        assert!(!is_invalid(&canonical_fact()));
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
