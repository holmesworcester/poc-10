//! Connection authenticator.
//!
//! POLICY. Authenticating a `connection` fact proves its fact boundary:
//!   1. LAYOUT. The bytes decode to a canonical sealed connection fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. OPEN. The sealed body opens with either local responder ephemeral
//!      context or local initiator endpoint context.
//!   4. MATERIAL. The opened connection matches the authenticated request and
//!      the public/private handshake material available for the local side.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};
use crate::protocol::auth::{endpoint, invite};
use crate::protocol::connection::ephemeral_secret;
use crate::protocol::connection::request;
use crate::protocol::connection::request::fact::{REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP};

use super::fact::ConnectionFact;
use super::{decode, encode};

pub(crate) struct ConnectionAuthenticator;

#[derive(Debug, Clone)]
pub(crate) enum AuthenticatedConnection {
    Responder {
        connection: ConnectionFact,
        request_need: ContextNeed,
        responder_secret_need: ContextNeed,
    },
    Initiator {
        connection: ConnectionFact,
        request_need: ContextNeed,
        endpoint_need: ContextNeed,
        initiator_need: ContextNeed,
    },
}

impl DecodedAuthenticator<super::Codec> for ConnectionAuthenticator {
    type Authenticated = AuthenticatedConnection;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        _decoded: (),
        context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        if let Err(error) = verify_fact_id(fact) {
            return Authentication::Invalid(error);
        }

        let request_id = match decode::connection_header_request_id(fact.body()) {
            Ok(request_id) => request_id,
            Err(error) => return Authentication::Invalid(error),
        };
        let request_need = request::project::connection_request_need(fact.id, request_id);
        let Some(request_fact) = context.payload_for(&request_need) else {
            return Authentication::need(request_need);
        };
        let request = match open_request_from_context(request_fact, context, fact.id) {
            Ok(request) => request,
            Err(_) => {
                return Authentication::needs([
                    request_need,
                    all_local_endpoint_need(fact.id),
                    all_ephemeral_secret_need(fact.id),
                ]);
            }
        };

        let responder_secret_need = all_ephemeral_secret_need(fact.id);
        for (_, secret_fact) in context.matched_payloads_for(&responder_secret_need) {
            if secret_fact.scope != FactScope::Local {
                return Authentication::Invalid(
                    "connection responder secret context must be local".to_string(),
                );
            }
            let secret = match ephemeral_secret::decode_fact_payload(secret_fact.body())
                .map_err(|_| "connection responder context is not an ephemeral secret".to_string())
            {
                Ok(secret) => secret,
                Err(error) => return Authentication::Invalid(error),
            };
            let Ok(connection) = decode::open_fact_as_responder(fact.body(), &secret) else {
                continue;
            };
            if let Err(error) = validate_connection(fact.id, &connection, &request) {
                return Authentication::Invalid(error);
            }
            if connection.responder_ephemeral_secret_fact_id != secret_fact.id {
                return Authentication::Invalid(
                    "connection responder secret id does not match".to_string(),
                );
            }
            if let Some(invite_need) = bootstrap_invite_need(fact.id, &request) {
                if context.payload_for(&invite_need).is_none() {
                    return Authentication::needs([
                        request_need,
                        responder_secret_need.clone(),
                        invite_need,
                    ]);
                }
            }
            if let Err(error) = validate_material(&connection, &request, context, fact.id, None) {
                return Authentication::Invalid(error);
            }
            return Authentication::Authenticated(crate::core::pipeline::AuthenticatedFact::new(
                fact,
                AuthenticatedConnection::Responder {
                    connection,
                    request_need,
                    responder_secret_need: responder_secret_need.clone(),
                },
            ));
        }

        let endpoint_need = all_local_endpoint_need(fact.id);
        for (_, endpoint_fact) in context.matched_payloads_for(&endpoint_need) {
            if endpoint_fact.scope != FactScope::Local {
                return Authentication::Invalid(
                    "connection endpoint context must be local".to_string(),
                );
            }
            let local_endpoint = match endpoint::decode_fact_payload(endpoint_fact.body())
                .map_err(|_| "connection endpoint context is malformed".to_string())
            {
                Ok(endpoint) => endpoint,
                Err(error) => return Authentication::Invalid(error),
            };
            let Ok(connection) = decode::open_fact(fact.body(), &local_endpoint) else {
                continue;
            };
            if let Err(error) = validate_connection(fact.id, &connection, &request) {
                return Authentication::Invalid(error);
            }
            let initiator_need = exact_need(
                fact.id,
                "connection_ephemeral_secret",
                FactScope::Local,
                connection.initiator_ephemeral_secret_fact_id,
            );
            let Some(initiator_fact) = context.payload_for(&initiator_need) else {
                return Authentication::needs([
                    request_need,
                    endpoint_need.clone(),
                    initiator_need,
                ]);
            };
            let initiator_secret =
                match ephemeral_secret::decode_fact_payload(initiator_fact.body()).map_err(|_| {
                    "connection initiator context is not an ephemeral secret".to_string()
                }) {
                    Ok(secret) => secret,
                    Err(error) => return Authentication::Invalid(error),
                };
            if let Some(invite_need) = bootstrap_invite_need(fact.id, &request) {
                if context.payload_for(&invite_need).is_none() {
                    return Authentication::needs([
                        request_need,
                        endpoint_need.clone(),
                        initiator_need,
                        invite_need,
                    ]);
                }
            }
            if let Err(error) = validate_material(
                &connection,
                &request,
                context,
                fact.id,
                Some(&initiator_secret),
            ) {
                return Authentication::Invalid(error);
            }
            return Authentication::Authenticated(crate::core::pipeline::AuthenticatedFact::new(
                fact,
                AuthenticatedConnection::Initiator {
                    connection,
                    request_need,
                    endpoint_need: endpoint_need.clone(),
                    initiator_need,
                },
            ));
        }

        Authentication::needs([request_need, responder_secret_need, endpoint_need])
    }
}

fn open_request_from_context(
    request_fact: &Fact,
    context: &ProjectionContext,
    owner: FactId,
) -> Result<request::fact::ConnectionRequestFact, String> {
    let endpoint_need = all_local_endpoint_need(owner);
    for (_, endpoint_fact) in context.matched_payloads_for(&endpoint_need) {
        if let Ok(endpoint) = endpoint::decode_fact_payload(endpoint_fact.body()) {
            if let Ok(request) = request::decode::open_fact(request_fact.body(), &endpoint) {
                return Ok(request);
            }
        }
    }
    let secret_need = all_ephemeral_secret_need(owner);
    for (_, secret_fact) in context.matched_payloads_for(&secret_need) {
        if let Ok(secret) = ephemeral_secret::decode_fact_payload(secret_fact.body()) {
            if let Ok(request) = request::decode::open_fact_as_sender(request_fact.body(), &secret)
            {
                return Ok(request);
            }
        }
    }
    Err("connection request context cannot be opened locally".to_string())
}

fn validate_connection(
    connection_id: FactId,
    connection: &ConnectionFact,
    request: &request::fact::ConnectionRequestFact,
) -> Result<(), String> {
    if connection_id == [0; 32] {
        return Err("connection id cannot be empty".to_string());
    }
    if connection.request_id == connection_id {
        return Err("connection cannot answer itself".to_string());
    }
    if request.from_endpoint != connection.to_endpoint {
        return Err("connection references another endpoint's request".to_string());
    }
    if request.to_endpoint != connection.from_endpoint {
        return Err("connection sender does not match request recipient".to_string());
    }
    if connection.initiator_ephemeral_secret_fact_id != request.initiator_ephemeral_secret_fact_id {
        return Err("connection initiator ephemeral does not match request".to_string());
    }
    if connection.responder_ephemeral_public_key == [0; 32] {
        return Err("connection responder ephemeral public key cannot be empty".to_string());
    }
    if connection.handshake_hash == [0; 32] || connection.connection_secret == [0; 32] {
        return Err("connection material cannot be empty".to_string());
    }
    Ok(())
}

fn validate_material(
    connection: &ConnectionFact,
    request: &request::fact::ConnectionRequestFact,
    context: &ProjectionContext,
    owner: FactId,
    initiator_secret: Option<&ephemeral_secret::fact::ConnectionEphemeralSecretFact>,
) -> Result<(), String> {
    let invite = match request.mode {
        REQUEST_MODE_BOOTSTRAP => {
            let need = exact_need(
                owner,
                "connection_invite_secret",
                FactScope::Local,
                request.invite_secret_fact_id,
            );
            let Some(fact) = context.payload_for(&need) else {
                return Err("connection bootstrap invite context is missing".to_string());
            };
            Some(
                invite::decode_fact_payload(fact.body())
                    .map_err(|_| "connection invite context is malformed".to_string())?,
            )
        }
        REQUEST_MODE_MEMBERSHIP => None,
        other => return Err(format!("unknown connection request mode {other}")),
    };
    if let Some(initiator_secret) = initiator_secret {
        let material = encode::initiator_material(
            connection.request_id,
            request,
            invite.as_ref(),
            initiator_secret,
            &connection.responder_ephemeral_public_key,
            connection.responder_addr,
            connection.initiator_addr,
        )?;
        if material.handshake_hash != connection.handshake_hash
            || material.connection_secret != connection.connection_secret
        {
            return Err("connection material does not match initiator handshake".to_string());
        }
    } else if encode::public_handshake_hash(
        connection.request_id,
        request,
        &connection.responder_ephemeral_public_key,
        connection.responder_addr,
        connection.initiator_addr,
    )? != connection.handshake_hash
    {
        return Err("connection handshake hash does not match transcript".to_string());
    }
    Ok(())
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

pub(super) fn exact_need(
    owner: FactId,
    role: &'static str,
    scope: FactScope,
    key: FactId,
) -> ContextNeed {
    ContextNeed::range(owner, role, scope, key, key)
}

fn bootstrap_invite_need(
    owner: FactId,
    request: &request::fact::ConnectionRequestFact,
) -> Option<ContextNeed> {
    (request.mode == REQUEST_MODE_BOOTSTRAP).then(|| {
        exact_need(
            owner,
            "connection_invite_secret",
            FactScope::Local,
            request.invite_secret_fact_id,
        )
    })
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::connection::connection::encode;
    use crate::protocol::connection::connection::fact::ConnectionFact;

    use super::ConnectionAuthenticator;

    fn canonical_fact() -> Fact {
        let initiator_secret = [9; 32];
        let responder_ephemeral_private_key = [10; 32];
        let connection = ConnectionFact {
            from_endpoint: [1; 32],
            to_endpoint: crypto::x25519_public_key(&initiator_secret),
            request_id: [3; 32],
            responder_addr: Some("127.0.0.1:41002".parse().unwrap()),
            initiator_addr: Some("127.0.0.1:41001".parse().unwrap()),
            initiator_ephemeral_secret_fact_id: [4; 32],
            responder_ephemeral_secret_fact_id: [5; 32],
            responder_ephemeral_public_key: crypto::x25519_public_key(
                &responder_ephemeral_private_key,
            ),
            handshake_hash: [7; 32],
            connection_secret: [8; 32],
        };
        let bytes = encode::seal_fact(&connection, &responder_ephemeral_private_key)
            .expect("seal connection fact");
        Fact::new(FactScope::Local, 100, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, super::AuthenticatedConnection> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => ConnectionAuthenticator::authenticate_decoded(
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
