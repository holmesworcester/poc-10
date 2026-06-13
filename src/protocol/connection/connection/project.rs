pub mod decode {
    //! Byte decoding for unified connection facts.
    //!
    //! Decoding proves only the fixed plaintext layout and the canonical sealed
    //! envelope shape (tag, version, length, header fields). Helpers here can open
    //! sealed bytes once a caller has ephemeral/endpoint context; the id check,
    //! opening decision, and handshake material proof live in the local `authenticate` module.

    use crate::core::crypto::{self, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES};
    use crate::core::wire;
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;
    use crate::protocol::connection::request::{
        encode::ADDR_BLOCK_BYTES, project::decode::decode_optional_addr,
    };

    use super::super::encode::{
        CONNECTION_PURPOSE, PLAINTEXT_FACT_BYTES, SEALED_FACT_BYTES, SEALED_HEADER_BYTES,
        SEAL_VERSION, TYPE_CONNECTION,
    };
    use super::super::fact::ConnectionFact;

    /// Sealed connection envelope codec.
    ///
    /// Decoding a connection fact proves only the canonical sealed layout. The id
    /// check, opening decision, and handshake material proof are the local `authenticate` module
    /// work, so the decoded payload is the unit envelope.
    pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionFact, String> {
        decode_plaintext(bytes)
    }

    pub fn decode_plaintext(bytes: &[u8]) -> Result<ConnectionFact, String> {
        wire::expect_len(bytes, PLAINTEXT_FACT_BYTES).map_err(wire_err)?;
        if bytes[0] != TYPE_CONNECTION {
            return Err("expected connection fact".to_string());
        }
        let mut from_endpoint = [0; 32];
        from_endpoint.copy_from_slice(&bytes[1..33]);
        let mut to_endpoint = [0; 32];
        to_endpoint.copy_from_slice(&bytes[33..65]);
        let mut request_id = [0; 32];
        request_id.copy_from_slice(&bytes[65..97]);
        let mut cursor = 97;
        let mut addr_bytes = [0u8; ADDR_BLOCK_BYTES];
        addr_bytes.copy_from_slice(&bytes[cursor..cursor + ADDR_BLOCK_BYTES]);
        let responder_addr = decode_optional_addr(&addr_bytes)?;
        cursor += ADDR_BLOCK_BYTES;
        addr_bytes.copy_from_slice(&bytes[cursor..cursor + ADDR_BLOCK_BYTES]);
        let initiator_addr = decode_optional_addr(&addr_bytes)?;
        cursor += ADDR_BLOCK_BYTES;
        let mut initiator_ephemeral_secret_fact_id = [0; 32];
        initiator_ephemeral_secret_fact_id.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        let mut responder_ephemeral_secret_fact_id = [0; 32];
        responder_ephemeral_secret_fact_id.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        let mut responder_ephemeral_public_key = [0; 32];
        responder_ephemeral_public_key.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        let mut handshake_hash = [0; 32];
        handshake_hash.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        let mut connection_secret = [0; 32];
        connection_secret.copy_from_slice(&bytes[cursor..cursor + 32]);
        Ok(ConnectionFact {
            from_endpoint,
            to_endpoint,
            request_id,
            responder_addr,
            initiator_addr,
            initiator_ephemeral_secret_fact_id,
            responder_ephemeral_secret_fact_id,
            responder_ephemeral_public_key,
            handshake_hash,
            connection_secret,
        })
    }

    pub fn is_sealed_fact(bytes: &[u8]) -> bool {
        bytes.first().copied() == Some(TYPE_CONNECTION) && bytes.len() == SEALED_FACT_BYTES
    }

    pub fn open_fact(
        bytes: &[u8],
        local_endpoint: &EndpointFact,
    ) -> Result<ConnectionFact, String> {
        let plaintext = open_fact_bytes(bytes, local_endpoint)?;
        decode_plaintext(&plaintext)
    }

    pub fn open_fact_bytes(bytes: &[u8], local_endpoint: &EndpointFact) -> Result<Vec<u8>, String> {
        validate_sealed_fact(bytes)?;
        let responder_ephemeral_public_key = connection_header_ephemeral_public_key(bytes)?;
        let to_endpoint = connection_header_to_endpoint(bytes)?;
        let nonce = nonce_from(&bytes[98..122]);
        let header = &bytes[..SEALED_HEADER_BYTES];
        let ciphertext = &bytes[SEALED_HEADER_BYTES..];
        let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
            &local_endpoint.secret,
            &responder_ephemeral_public_key,
            CONNECTION_PURPOSE,
            header,
            &nonce,
            ciphertext,
        )?;
        let connection = decode_plaintext(&plaintext)?;
        if connection.to_endpoint != local_endpoint.endpoint
            || connection.to_endpoint != to_endpoint
        {
            return Err("sealed connection is addressed to another endpoint".to_string());
        }
        validate_header_match(bytes, &connection)?;
        Ok(plaintext)
    }

    pub fn open_fact_as_responder(
        bytes: &[u8],
        responder_ephemeral: &ConnectionEphemeralSecretFact,
    ) -> Result<ConnectionFact, String> {
        let plaintext = open_fact_bytes_as_responder(bytes, responder_ephemeral)?;
        decode_plaintext(&plaintext)
    }

    pub fn open_fact_bytes_as_responder(
        bytes: &[u8],
        responder_ephemeral: &ConnectionEphemeralSecretFact,
    ) -> Result<Vec<u8>, String> {
        validate_sealed_fact(bytes)?;
        let responder_ephemeral_public_key = connection_header_ephemeral_public_key(bytes)?;
        if responder_ephemeral.ephemeral_public_key != responder_ephemeral_public_key {
            return Err("sealed connection responder ephemeral does not match header".to_string());
        }
        let to_endpoint = connection_header_to_endpoint(bytes)?;
        let nonce = nonce_from(&bytes[98..122]);
        let header = &bytes[..SEALED_HEADER_BYTES];
        let ciphertext = &bytes[SEALED_HEADER_BYTES..];
        let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
            &responder_ephemeral.ephemeral_private_key,
            &to_endpoint,
            CONNECTION_PURPOSE,
            header,
            &nonce,
            ciphertext,
        )?;
        let connection = decode_plaintext(&plaintext)?;
        if connection.from_endpoint != responder_ephemeral.owner_endpoint {
            return Err("sealed connection responder does not own connection".to_string());
        }
        validate_header_match(bytes, &connection)?;
        Ok(plaintext)
    }

    pub fn validate_sealed_fact(bytes: &[u8]) -> Result<(), String> {
        if bytes.len() != SEALED_FACT_BYTES {
            return Err("sealed connection has wrong length".to_string());
        }
        if bytes[0] != TYPE_CONNECTION || bytes[1] != SEAL_VERSION {
            return Err("sealed connection has unsupported header".to_string());
        }
        Ok(())
    }

    pub fn connection_header_ephemeral_public_key(bytes: &[u8]) -> Result<[u8; 32], String> {
        validate_sealed_fact(bytes)?;
        let mut key = [0; 32];
        key.copy_from_slice(&bytes[2..34]);
        Ok(key)
    }

    pub fn connection_header_to_endpoint(bytes: &[u8]) -> Result<[u8; 32], String> {
        validate_sealed_fact(bytes)?;
        let mut key = [0; 32];
        key.copy_from_slice(&bytes[34..66]);
        Ok(key)
    }

    pub fn connection_header_request_id(bytes: &[u8]) -> Result<[u8; 32], String> {
        validate_sealed_fact(bytes)?;
        let mut key = [0; 32];
        key.copy_from_slice(&bytes[66..98]);
        Ok(key)
    }

    fn validate_header_match(bytes: &[u8], connection: &ConnectionFact) -> Result<(), String> {
        if connection.responder_ephemeral_public_key
            != connection_header_ephemeral_public_key(bytes)?
        {
            return Err("sealed connection inner ephemeral key does not match header".to_string());
        }
        if connection.to_endpoint != connection_header_to_endpoint(bytes)? {
            return Err("sealed connection inner endpoint does not match header".to_string());
        }
        if connection.request_id != connection_header_request_id(bytes)? {
            return Err("sealed connection inner request id does not match header".to_string());
        }
        Ok(())
    }

    fn nonce_from(bytes: &[u8]) -> XChaCha20Poly1305Nonce {
        let mut nonce = [0; XCHACHA20_POLY1305_NONCE_BYTES];
        nonce.copy_from_slice(bytes);
        nonce
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    #[cfg(test)]
    mod tests {
        use crate::protocol::connection::connection::encode::{
            encode_fact, PLAINTEXT_FACT_BYTES, TYPE_CONNECTION,
        };

        use super::*;

        fn fact() -> ConnectionFact {
            ConnectionFact {
                from_endpoint: [1; 32],
                to_endpoint: [2; 32],
                request_id: [3; 32],
                responder_addr: Some("127.0.0.1:41002".parse().unwrap()),
                initiator_addr: Some("127.0.0.1:41001".parse().unwrap()),
                initiator_ephemeral_secret_fact_id: [4; 32],
                responder_ephemeral_secret_fact_id: [5; 32],
                responder_ephemeral_public_key: [6; 32],
                handshake_hash: [7; 32],
                connection_secret: [8; 32],
            }
        }

        #[test]
        fn connection_roundtrips_fixed_width() {
            let bytes = encode_fact(&fact()).expect("encode");
            assert_eq!(bytes.len(), PLAINTEXT_FACT_BYTES);
            assert_eq!(decode_fact(&bytes).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag_or_length() {
            let mut bytes = encode_fact(&fact()).expect("encode");
            bytes[0] = TYPE_CONNECTION.wrapping_add(1);
            assert!(decode_fact(&bytes).is_err());

            let mut short = encode_fact(&fact()).expect("encode");
            short.pop();
            assert!(decode_fact(&short).is_err());
        }
    }
}
pub mod authenticate {
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
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};
    use crate::protocol::auth::endpoint;
    use crate::protocol::connection::ephemeral_secret;
    use crate::protocol::connection::request;
    use crate::protocol::connection::request::fact::{
        REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP,
    };

    use super::super::encode;
    use super::super::fact::ConnectionFact;
    use super::decode;

    #[derive(Debug, Clone)]
    pub(crate) enum AuthenticatedConnection {
        Responder {
            connection: ConnectionFact,
            request_need: ContextNeed,
            request_opener_need: ContextNeed,
            responder_secret_need: ContextNeed,
            invite_need: Option<ContextNeed>,
        },
        Initiator {
            connection: ConnectionFact,
            request_need: ContextNeed,
            request_opener_need: ContextNeed,
            endpoint_need: ContextNeed,
            initiator_need: ContextNeed,
            invite_need: Option<ContextNeed>,
        },
    }

    #[derive(Debug, Clone)]
    struct OpenedRequest {
        request: request::fact::ConnectionRequestFact,
        opener_need: ContextNeed,
    }

    pub(crate) enum Authentication {
        Authenticated(AuthenticatedConnection),
        NeedsContext(Vec<ContextNeed>),
    }

    pub(crate) fn authenticate(
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<Authentication, String> {
        if let Err(error) = verify_fact_id(fact) {
            return Err(error);
        }

        let request_id = match decode::connection_header_request_id(fact.body()) {
            Ok(request_id) => request_id,
            Err(error) => return Err(error),
        };
        let request_need = request::project::connection_request_need(fact.id, request_id);
        let Some(request_fact) = context.payload_for(&request_need) else {
            return Ok(Authentication::NeedsContext(vec![request_need]));
        };
        let opened_request = match open_request_from_context(request_fact, context, fact.id) {
            Ok(opened_request) => opened_request,
            Err(_) => {
                return Ok(Authentication::NeedsContext(vec![
                    request_need,
                    all_local_endpoint_need(fact.id),
                    all_ephemeral_secret_need(fact.id),
                ]));
            }
        };
        let request = opened_request.request;
        let request_opener_need = opened_request.opener_need;

        let responder_secret_need = all_ephemeral_secret_need(fact.id);
        for (_, secret_fact) in context.matched_payloads_for(&responder_secret_need) {
            if secret_fact.scope != FactScope::Local {
                return Err("connection responder secret context must be local".to_string());
            }
            let secret = match ephemeral_secret::decode_fact_payload(secret_fact.body())
                .map_err(|_| "connection responder context is not an ephemeral secret".to_string())
            {
                Ok(secret) => secret,
                Err(error) => return Err(error),
            };
            let Ok(connection) = decode::open_fact_as_responder(fact.body(), &secret) else {
                continue;
            };
            if let Err(error) = validate_connection(fact.id, &connection, &request) {
                return Err(error);
            }
            if connection.responder_ephemeral_secret_fact_id != secret_fact.id {
                return Err("connection responder secret id does not match".to_string());
            }
            let invite_need = bootstrap_invite_need(fact.id, &request);
            if let Some(invite_need) = &invite_need {
                if context.payload_for(invite_need).is_none() {
                    return Ok(Authentication::NeedsContext(vec![
                        request_need.clone(),
                        request_opener_need.clone(),
                        responder_secret_need.clone(),
                        invite_need.clone(),
                    ]));
                }
            }
            if let Err(error) = validate_material(&connection, &request, context, fact.id, None) {
                return Err(error);
            }
            return Ok(Authentication::Authenticated(
                AuthenticatedConnection::Responder {
                    connection,
                    request_need: request_need.clone(),
                    request_opener_need: request_opener_need.clone(),
                    responder_secret_need: responder_secret_need.clone(),
                    invite_need,
                },
            ));
        }

        let endpoint_need = all_local_endpoint_need(fact.id);
        for (_, endpoint_fact) in context.matched_payloads_for(&endpoint_need) {
            if endpoint_fact.scope != FactScope::Local {
                return Err("connection endpoint context must be local".to_string());
            }
            let local_endpoint = match endpoint::decode_fact_payload(endpoint_fact.body())
                .map_err(|_| "connection endpoint context is malformed".to_string())
            {
                Ok(endpoint) => endpoint,
                Err(error) => return Err(error),
            };
            let Ok(connection) = decode::open_fact(fact.body(), &local_endpoint) else {
                continue;
            };
            if let Err(error) = validate_connection(fact.id, &connection, &request) {
                return Err(error);
            }
            let initiator_need = exact_need(
                fact.id,
                "connection_ephemeral_secret",
                FactScope::Local,
                connection.initiator_ephemeral_secret_fact_id,
            );
            let Some(initiator_fact) = context.payload_for(&initiator_need) else {
                return Ok(Authentication::NeedsContext(vec![
                    request_need.clone(),
                    request_opener_need.clone(),
                    endpoint_need.clone(),
                    initiator_need,
                ]));
            };
            let initiator_secret =
                match ephemeral_secret::decode_fact_payload(initiator_fact.body()).map_err(|_| {
                    "connection initiator context is not an ephemeral secret".to_string()
                }) {
                    Ok(secret) => secret,
                    Err(error) => return Err(error),
                };
            let invite_need = bootstrap_invite_need(fact.id, &request);
            if let Some(invite_need) = &invite_need {
                if context.payload_for(invite_need).is_none() {
                    return Ok(Authentication::NeedsContext(vec![
                        request_need.clone(),
                        request_opener_need.clone(),
                        endpoint_need.clone(),
                        initiator_need,
                        invite_need.clone(),
                    ]));
                }
            }
            if let Err(error) = validate_material(
                &connection,
                &request,
                context,
                fact.id,
                Some(&initiator_secret),
            ) {
                return Err(error);
            }
            return Ok(Authentication::Authenticated(
                AuthenticatedConnection::Initiator {
                    connection,
                    request_need: request_need.clone(),
                    request_opener_need: request_opener_need.clone(),
                    endpoint_need: endpoint_need.clone(),
                    initiator_need,
                    invite_need,
                },
            ));
        }

        Ok(Authentication::NeedsContext(vec![
            request_need,
            request_opener_need,
            responder_secret_need,
            endpoint_need,
        ]))
    }

    fn open_request_from_context(
        request_fact: &Fact,
        context: &ProjectionContext,
        owner: FactId,
    ) -> Result<OpenedRequest, String> {
        let endpoint_need = all_local_endpoint_need(owner);
        for (_, endpoint_fact) in context.matched_payloads_for(&endpoint_need) {
            if let Ok(endpoint) = endpoint::decode_fact_payload(endpoint_fact.body()) {
                if let Ok(request) =
                    request::project::decode::open_fact(request_fact.body(), &endpoint)
                {
                    return Ok(OpenedRequest {
                        opener_need: endpoint_need.clone(),
                        request,
                    });
                }
            }
        }
        let secret_need = all_ephemeral_secret_need(owner);
        for (_, secret_fact) in context.matched_payloads_for(&secret_need) {
            if let Ok(secret) = ephemeral_secret::decode_fact_payload(secret_fact.body()) {
                if let Ok(request) =
                    request::project::decode::open_fact_as_sender(request_fact.body(), &secret)
                {
                    return Ok(OpenedRequest {
                        opener_need: secret_need.clone(),
                        request,
                    });
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
        if connection.initiator_ephemeral_secret_fact_id
            != request.initiator_ephemeral_secret_fact_id
        {
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
                    request::project::authenticate::invite_secret_from_context_fact(
                        fact,
                        request.invite_secret_fact_id,
                    )?,
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
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::connection::connection::encode;
        use crate::protocol::connection::connection::fact::ConnectionFact;

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

        fn authenticate(fact: &Fact) -> Result<super::Authentication, String> {
            super::super::decode::validate_sealed_fact(fact.body())?;
            super::authenticate(fact, &ProjectionContext::default())
        }

        fn is_invalid(fact: &Fact) -> bool {
            authenticate(fact).is_err()
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
}
pub mod adapt {
    //! Connection semantic adapter.
    //!
    //! The authenticated opened connection is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::authenticate::AuthenticatedConnection;

    pub(crate) fn adapt(
        source: AuthenticatedConnection,
    ) -> Result<AuthenticatedConnection, String> {
        Ok(source)
    }
}

// Unified connection projector.
//
// The same sealed connection fact is projected on both sides after
// the local `authenticate` module has resolved the request, opened the sealed connection, and
// verified handshake material. The responder branch sends the connection fact;
// the initiator branch pairs it with the receive observation and seeds sync.
// During replay this live session state is intentionally not rebuilt; the
// retained fact remains evidence, but the projector returns no effects.
//
// POLICY. A connection is admitted iff:
//   1. STRUCTURAL. The fact is local; primary byte shape, id, request opening,
//      connection opening, and handshake material have already been
//      authenticated.
//   2. CONTEXT. Projection observes close and receive-observation context.
//   3. MATERIALIZE. Live connections write one connection row; close context
//      deletes that row and purges the connection fact.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::{RowMutation, TableDelete};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::connection::close;
use crate::protocol::connection::connection::{
    connection_key, connection_row, ConnectionRowFields, CONNECTION_ROWS,
};
use crate::protocol::connection::fact_receipt::fact::ReceiptPathInput;
use crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION;
use crate::protocol::connection::fact_receipt::project::connection_fact_receipt_for_path;
use crate::protocol::connection::frame_observation;
use crate::protocol::connection::request;
use crate::protocol::connection::send_network_frame::{
    send_network_frame_intent, SendNetworkFrame,
};
use crate::protocol::sync::seed_connection::{seed_connection_sync_intent, SeedConnectionSync};

use super::fact::ConnectionFact;
use authenticate::AuthenticatedConnection;

const CONNECTION_ROLE: &str = "connection";

pub fn connection_need(owner: FactId, connection_id: FactId) -> ContextNeed {
    ContextNeed::range(
        owner,
        CONNECTION_ROLE,
        FactScope::Local,
        connection_id,
        connection_id,
    )
}

pub fn connection_offer(owner: FactId, connection_id: FactId) -> ContextOffer {
    ContextOffer::range(
        owner,
        CONNECTION_ROLE,
        FactScope::Local,
        connection_id,
        connection_id,
    )
}

/// Projector route metadata for the connection fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("connection::connection::project::ConnectionProjector");

#[derive(Debug, Clone, Default)]
pub struct ConnectionProjector;

impl ConnectionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        decode::validate_sealed_fact(fact.body())?;
        match authenticate::authenticate(fact, context)? {
            authenticate::Authentication::Authenticated(authenticated) => {
                let semantic = adapt::adapt(authenticated)?;
                self.project_semantic(fact, semantic, context)
            }
            authenticate::Authentication::NeedsContext(needs) => Ok(needs
                .into_iter()
                .fold(ProjectionOutput::new(), |output, need| output.need(need))),
        }
    }
}

impl ConnectionProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        semantic: AuthenticatedConnection,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("connection fact must have local scope".to_string());
        }
        if context.is_replay() {
            return Ok(ProjectionOutput::new());
        }
        // 2. Context.
        let close_need = close::connection_closed_need(fact.id, fact.id);
        if let Some(close_fact) = context.payload_for(&close_need) {
            if close_fact.scope != FactScope::Local {
                return Err("connection close context must be local".to_string());
            }
            return Ok(ProjectionOutput::new()
                .row_mutation(RowMutation::DeleteRow(TableDelete {
                    table: CONNECTION_ROWS,
                    key: connection_key(&fact.id),
                }))
                .purge_self(fact.id));
        }

        // 3. Materialize.
        match semantic {
            AuthenticatedConnection::Responder {
                connection,
                request_need,
                request_opener_need,
                responder_secret_need,
                invite_need,
            } => {
                let needs = ConnectionNeeds::responder(
                    close_need,
                    request_need,
                    request_opener_need,
                    responder_secret_need,
                    invite_need,
                );
                let output = needs.apply_to(materialized_output(fact, &connection));
                Ok(output
                    .offer(request::project::connection_for_request_offer(
                        fact.id,
                        connection.request_id,
                    ))
                    .intent(seed_connection_sync_intent(SeedConnectionSync {
                        connection_id: fact.id,
                    }))
                    .local_intent(send_network_frame_intent(SendNetworkFrame {
                        routing_key: fact.id,
                        frame: fact.body().to_vec(),
                    })))
            }
            AuthenticatedConnection::Initiator {
                connection,
                request_need,
                request_opener_need,
                endpoint_need,
                initiator_need,
                invite_need,
            } => project_initiator_connection(
                fact,
                &connection,
                context,
                ConnectionNeeds::initiator(
                    close_need,
                    request_need,
                    request_opener_need,
                    endpoint_need,
                    initiator_need,
                    invite_need,
                ),
            ),
        }
    }
}

fn project_initiator_connection(
    fact: &Fact,
    connection: &ConnectionFact,
    context: &ProjectionContext,
    needs: ConnectionNeeds,
) -> Result<ProjectionOutput, String> {
    let observation_need = exact_need(
        fact.id,
        "connection_frame_observation",
        FactScope::Local,
        fact.id,
    );
    let needs = needs.with_observation(observation_need.clone());
    let Some(observation_fact) = context.payload_for(&observation_need) else {
        return Ok(needs.apply_to(ProjectionOutput::new()));
    };
    let observation = frame_observation::project::decode::decode_fact(observation_fact.body())
        .map_err(|_| "connection observation context is malformed".to_string())?;
    if observation.frame_fact_id != fact.id {
        return Err("connection observation targets another fact".to_string());
    }
    let receipt = connection_fact_receipt_for_path(ReceiptPathInput {
        received_fact_id: fact.id,
        origin_addr: observation.origin_addr.bytes(),
        local_endpoint_id: connection.to_endpoint,
        sender_endpoint_id: connection.from_endpoint,
        receive_path: RECEIVE_PATH_CONNECTION,
        connection_id: Some(fact.id),
        request_id: Some(connection.request_id),
        frame_hash: crypto::hash(fact.body()),
        received_at_local_ms: observation.received_at_local_ms,
    })?;
    Ok(needs
        .apply_to(materialized_output(fact, connection))
        .fact(receipt)
        .intent(seed_connection_sync_intent(SeedConnectionSync {
            connection_id: fact.id,
        })))
}

fn materialized_output(fact: &Fact, connection: &ConnectionFact) -> ProjectionOutput {
    ProjectionOutput::new()
        .offer(connection_offer(fact.id, fact.id))
        .row_mutation(RowMutation::PutRow(
            connection_row(ConnectionRowFields {
                connection_id: fact.id,
                from_endpoint: connection.from_endpoint,
                to_endpoint: connection.to_endpoint,
                request_id: connection.request_id,
                responder_ephemeral_public_key: connection.responder_ephemeral_public_key,
                handshake_hash: connection.handshake_hash,
                connection_secret: connection.connection_secret,
                responder_addr: connection.responder_addr,
                initiator_addr: connection.initiator_addr,
            })
            .expect("connection row encodes"),
        ))
}

fn exact_need(owner: FactId, role: &'static str, scope: FactScope, key: FactId) -> ContextNeed {
    authenticate::exact_need(owner, role, scope, key)
}

#[derive(Debug, Clone)]
struct ConnectionNeeds {
    close: ContextNeed,
    request: ContextNeed,
    request_opener: ContextNeed,
    responder_secret: Option<ContextNeed>,
    endpoint: Option<ContextNeed>,
    initiator: Option<ContextNeed>,
    observation: Option<ContextNeed>,
    invite: Option<ContextNeed>,
}

impl ConnectionNeeds {
    fn responder(
        close: ContextNeed,
        request: ContextNeed,
        request_opener: ContextNeed,
        responder_secret: ContextNeed,
        invite: Option<ContextNeed>,
    ) -> Self {
        Self {
            close,
            request,
            request_opener,
            responder_secret: Some(responder_secret),
            endpoint: None,
            initiator: None,
            observation: None,
            invite,
        }
    }

    fn initiator(
        close: ContextNeed,
        request: ContextNeed,
        request_opener: ContextNeed,
        endpoint: ContextNeed,
        initiator: ContextNeed,
        invite: Option<ContextNeed>,
    ) -> Self {
        Self {
            close,
            request,
            request_opener,
            responder_secret: None,
            endpoint: Some(endpoint),
            initiator: Some(initiator),
            observation: None,
            invite,
        }
    }

    fn with_observation(mut self, observation: ContextNeed) -> Self {
        self.observation = Some(observation);
        self
    }

    fn apply_to(&self, output: ProjectionOutput) -> ProjectionOutput {
        let mut output = output
            .need(self.close.clone())
            .need(self.request.clone())
            .need(self.request_opener.clone());
        for need in [
            &self.responder_secret,
            &self.endpoint,
            &self.initiator,
            &self.observation,
            &self.invite,
        ]
        .into_iter()
        .flatten()
        {
            output = output.need(need.clone());
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::project_fact::ProjectionMode;
    use crate::protocol::connection::send_network_frame::SEND_NETWORK_FRAME;
    use crate::protocol::sync::seed_connection::SEED_CONNECTION_SYNC;

    fn connection_fact() -> ConnectionFact {
        ConnectionFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            request_id: [3; 32],
            responder_addr: None,
            initiator_addr: None,
            initiator_ephemeral_secret_fact_id: [4; 32],
            responder_ephemeral_secret_fact_id: [5; 32],
            responder_ephemeral_public_key: [6; 32],
            handshake_hash: [7; 32],
            connection_secret: [8; 32],
        }
    }

    #[test]
    fn responder_projection_sends_response_and_seeds_sync() {
        let fact = Fact::new(FactScope::Local, 10, vec![49, 1, 2, 3]);
        let request_need = request::project::connection_request_need(fact.id, [3; 32]);
        let request_opener_need = authenticate::all_local_endpoint_need(fact.id);
        let responder_secret_need = authenticate::all_ephemeral_secret_need(fact.id);
        let invite_need = authenticate::exact_need(
            fact.id,
            "connection_invite_secret",
            FactScope::Local,
            [9; 32],
        );

        let output = ConnectionProjector::new()
            .project_semantic(
                &fact,
                AuthenticatedConnection::Responder {
                    connection: connection_fact(),
                    request_need,
                    request_opener_need,
                    responder_secret_need,
                    invite_need: Some(invite_need),
                },
                &ProjectionContext::default(),
            )
            .expect("project responder connection");

        assert!(output
            .needs
            .iter()
            .any(|need| need.role.as_str() == "connection_invite_secret"));
        assert!(output
            .effects
            .intents
            .iter()
            .any(|intent| intent.kind.as_str() == SEED_CONNECTION_SYNC));
        assert!(output
            .effects
            .local_intents
            .iter()
            .any(|intent| intent.kind.as_str() == SEND_NETWORK_FRAME));
    }

    #[test]
    fn replay_projection_does_not_rebuild_live_connection_state() {
        let fact = Fact::new(FactScope::Local, 10, vec![49, 1, 2, 3]);
        let output = ConnectionProjector::new()
            .project_semantic(
                &fact,
                AuthenticatedConnection::Responder {
                    connection: connection_fact(),
                    request_need: request::project::connection_request_need(fact.id, [3; 32]),
                    request_opener_need: authenticate::all_local_endpoint_need(fact.id),
                    responder_secret_need: authenticate::all_ephemeral_secret_need(fact.id),
                    invite_need: None,
                },
                &ProjectionContext::default().with_mode(ProjectionMode::Replay),
            )
            .expect("replay connection");

        assert!(output.offers.is_empty());
        assert!(output.needs.is_empty());
        assert!(output.effects.row_mutations.is_empty());
        assert!(output.effects.intents.is_empty());
        assert!(output.effects.local_intents.is_empty());
    }
}
