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

    // Tests. Ordered most-central-first: full roundtrip leads, then tag/length guards.
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
                let (endpoint_need, secret_need) = request_opener_needs(fact.id, request_fact)?;
                return Ok(Authentication::NeedsContext(vec![
                    request_need,
                    endpoint_need,
                    secret_need,
                ]));
            }
        };
        let request = opened_request.request;
        let request_opener_need = opened_request.opener_need;

        let responder_secret_need = ephemeral_secret_public_key_need(
            fact.id,
            decode::connection_header_ephemeral_public_key(fact.body())?,
        );
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
                if context.offer_for(invite_need).is_none() {
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

        let endpoint_need =
            local_endpoint_need(fact.id, decode::connection_header_to_endpoint(fact.body())?);
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
                if context.offer_for(invite_need).is_none() {
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
        let (endpoint_need, secret_need) = request_opener_needs(owner, request_fact)?;
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

    fn request_opener_needs(
        owner: FactId,
        request_fact: &Fact,
    ) -> Result<(ContextNeed, ContextNeed), String> {
        Ok((
            local_endpoint_need(
                owner,
                request::project::decode::request_header_to_endpoint(request_fact.body())?,
            ),
            ephemeral_secret_public_key_need(
                owner,
                request::project::decode::request_header_ephemeral_public_key(request_fact.body())?,
            ),
        ))
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

    pub(super) fn ephemeral_secret_public_key_need(
        owner: FactId,
        public_key: FactId,
    ) -> ContextNeed {
        exact_need(
            owner,
            ephemeral_secret::project::CONNECTION_EPHEMERAL_SECRET_PUBLIC_KEY_ROLE,
            FactScope::Local,
            public_key,
        )
    }

    pub(super) fn local_endpoint_need(owner: FactId, endpoint_id: FactId) -> ContextNeed {
        exact_need(owner, "auth_local_endpoint", FactScope::Local, endpoint_id)
    }

    pub(super) fn exact_need(
        owner: FactId,
        role: &'static str,
        scope: FactScope,
        key: FactId,
    ) -> ContextNeed {
        ContextNeed::for_key(owner, role, scope, key)
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

    // Tests. Ordered most-central-first: canonical happy path, then context-park gates, then rejection guards.
    #[cfg(test)]
    mod tests {
        use crate::core::context::{ContextNeed, ContextOffer};
        use crate::core::crypto;
        use crate::core::facts::{Fact, FactId, FactScope};
        use crate::core::project_fact::{MatchedContext, ProjectionContext};
        use crate::protocol::auth::endpoint::encode as endpoint_encode;
        use crate::protocol::auth::endpoint::fact::EndpointFact;
        use crate::protocol::connection::connection::encode;
        use crate::protocol::connection::connection::fact::ConnectionFact;
        use crate::protocol::connection::request::encode as request_encode;
        use crate::protocol::connection::request::fact::{
            ConnectionRequestFact, REQUEST_MODE_MEMBERSHIP,
        };

        fn canonical_fact() -> Fact {
            canonical_connection_fact([3; 32], crypto::x25519_public_key(&[9; 32]))
        }

        fn canonical_connection_fact(request_id: FactId, to_endpoint: FactId) -> Fact {
            let responder_ephemeral_private_key = [10; 32];
            let connection = ConnectionFact {
                from_endpoint: [1; 32],
                to_endpoint,
                request_id,
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

        fn sealed_request_fact(
            from_endpoint: FactId,
            to_endpoint: FactId,
            initiator_ephemeral_private_key: FactId,
        ) -> Fact {
            let request = ConnectionRequestFact {
                mode: REQUEST_MODE_MEMBERSHIP,
                from_endpoint,
                to_endpoint,
                nonce: [3; 32],
                dialed_addr: None,
                initiator_addr: None,
                invite_fact_id: [0; 32],
                bootstrap_hash: [0; 32],
                invite_secret_fact_id: [0; 32],
                invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
                initiator_endpoint_shared_id: [4; 32],
                endpoint_signature: [5; crypto::ED25519_SIGNATURE_BYTES],
                initiator_ephemeral_secret_fact_id: [6; 32],
                initiator_ephemeral_public_key: crypto::x25519_public_key(
                    &initiator_ephemeral_private_key,
                ),
            };
            Fact::new(
                FactScope::Global,
                99,
                request_encode::seal_fact(&request, &initiator_ephemeral_private_key)
                    .expect("seal request"),
            )
        }

        fn request_match(owner: FactId, request_fact: &Fact) -> MatchedContext {
            MatchedContext {
                need: crate::protocol::connection::request::project::connection_request_need(
                    owner,
                    request_fact.id,
                ),
                offer: crate::protocol::connection::request::project::connection_request_offer(
                    request_fact.id,
                    request_fact.id,
                ),
                payload: request_fact.clone(),
            }
        }

        fn endpoint_match(owner: FactId, endpoint: EndpointFact) -> MatchedContext {
            let endpoint_fact = Fact::new(
                FactScope::Local,
                101,
                endpoint_encode::encode_fact(&endpoint).expect("endpoint fact"),
            );
            MatchedContext {
                need: super::local_endpoint_need(owner, endpoint.endpoint),
                offer: ContextOffer::for_key(
                    endpoint_fact.id,
                    "auth_local_endpoint",
                    FactScope::Local,
                    endpoint.endpoint,
                ),
                payload: endpoint_fact,
            }
        }

        fn assert_exact_need(need: &ContextNeed, role: &str, key: FactId) {
            assert_eq!(need.role.as_str(), role);
            assert_eq!(need.start_key.as_bytes(), key);
            assert_eq!(need.end_key.as_bytes(), key);
        }

        fn exact_need_with_key<'a>(
            needs: &'a [ContextNeed],
            role: &str,
            key: FactId,
        ) -> &'a ContextNeed {
            needs
                .iter()
                .find(|need| {
                    need.role.as_str() == role
                        && need.start_key.as_bytes() == key
                        && need.end_key.as_bytes() == key
                })
                .expect("exact need")
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
        fn missing_request_opener_needs_are_exact_from_request_header() {
            let initiator_endpoint = crypto::x25519_public_key(&[11; 32]);
            let responder_endpoint = crypto::x25519_public_key(&[12; 32]);
            let initiator_ephemeral_private_key = [13; 32];
            let request_fact = sealed_request_fact(
                initiator_endpoint,
                responder_endpoint,
                initiator_ephemeral_private_key,
            );
            let connection_fact = canonical_connection_fact(request_fact.id, initiator_endpoint);
            let context = ProjectionContext::from_matches(vec![request_match(
                connection_fact.id,
                &request_fact,
            )]);

            let super::Authentication::NeedsContext(needs) =
                super::authenticate(&connection_fact, &context).expect("authenticate")
            else {
                panic!("connection should park on request opener context");
            };

            assert_exact_need(
                exact_need_with_key(&needs, "auth_local_endpoint", responder_endpoint),
                "auth_local_endpoint",
                responder_endpoint,
            );
            assert_exact_need(
                exact_need_with_key(
                    &needs,
                    crate::protocol::connection::ephemeral_secret::project::CONNECTION_EPHEMERAL_SECRET_PUBLIC_KEY_ROLE,
                    crypto::x25519_public_key(&initiator_ephemeral_private_key),
                ),
                crate::protocol::connection::ephemeral_secret::project::CONNECTION_EPHEMERAL_SECRET_PUBLIC_KEY_ROLE,
                crypto::x25519_public_key(&initiator_ephemeral_private_key),
            );
        }

        #[test]
        fn missing_connection_openers_need_exact_header_context() {
            let initiator_endpoint = crypto::x25519_public_key(&[11; 32]);
            let responder_secret = [12; 32];
            let responder_endpoint = crypto::x25519_public_key(&responder_secret);
            let initiator_ephemeral_private_key = [13; 32];
            let responder_ephemeral_public_key = crypto::x25519_public_key(&[14; 32]);
            let request_fact = sealed_request_fact(
                initiator_endpoint,
                responder_endpoint,
                initiator_ephemeral_private_key,
            );
            let connection = ConnectionFact {
                from_endpoint: responder_endpoint,
                to_endpoint: initiator_endpoint,
                request_id: request_fact.id,
                responder_addr: None,
                initiator_addr: None,
                initiator_ephemeral_secret_fact_id: [6; 32],
                responder_ephemeral_secret_fact_id: [7; 32],
                responder_ephemeral_public_key,
                handshake_hash: [8; 32],
                connection_secret: [9; 32],
            };
            let connection_fact = Fact::new(
                FactScope::Local,
                100,
                encode::seal_fact(&connection, &[14; 32]).expect("seal connection"),
            );
            let responder_endpoint_fact = EndpointFact {
                endpoint: responder_endpoint,
                secret: responder_secret,
                signing_public_key: crypto::ed25519_public_key(&[15; 32]),
                signing_secret: [15; 32],
            };
            let context = ProjectionContext::from_matches(vec![
                request_match(connection_fact.id, &request_fact),
                endpoint_match(connection_fact.id, responder_endpoint_fact),
            ]);

            let super::Authentication::NeedsContext(needs) =
                super::authenticate(&connection_fact, &context).expect("authenticate")
            else {
                panic!("connection should park on connection opener context");
            };

            assert_exact_need(
                exact_need_with_key(&needs, "auth_local_endpoint", initiator_endpoint),
                "auth_local_endpoint",
                initiator_endpoint,
            );
            assert_exact_need(
                exact_need_with_key(
                    &needs,
                    crate::protocol::connection::ephemeral_secret::project::CONNECTION_EPHEMERAL_SECRET_PUBLIC_KEY_ROLE,
                    responder_ephemeral_public_key,
                ),
                crate::protocol::connection::ephemeral_secret::project::CONNECTION_EPHEMERAL_SECRET_PUBLIC_KEY_ROLE,
                responder_ephemeral_public_key,
            );
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

use crate::core::context::{ContextNeed, ContextOffer, ContextOfferClaim};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::{RowMutation, Value};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::connection::close;
use crate::protocol::connection::connection::{
    connection_row, ConnectionRowFields, CONNECTION_TABLE,
};
use crate::protocol::connection::fact_receipt::fact::ReceiptPathInput;
use crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION;
use crate::protocol::connection::fact_receipt::project::connection_fact_receipt_for_path;
use crate::protocol::connection::frame_observation;
use crate::protocol::connection::queue_outgoing_frame::{
    queue_outgoing_frame_intent, QueueOutgoingFrame,
};
use crate::protocol::connection::request;
use crate::protocol::sync::seed_connection::{seed_connection_sync_intent, SeedConnectionSync};

use super::fact::ConnectionFact;
use authenticate::AuthenticatedConnection;

const CONNECTION_ROLE: &str = "connection";

pub fn connection_need(owner: FactId, connection_id: FactId) -> ContextNeed {
    ContextNeed::for_key(owner, CONNECTION_ROLE, FactScope::Local, connection_id)
}

pub fn connection_offer(owner: FactId, connection_id: FactId) -> ContextOffer {
    ContextOffer::for_key(owner, CONNECTION_ROLE, FactScope::Local, connection_id)
}

pub fn connection_offer_claim(connection_id: FactId) -> ContextOfferClaim {
    ContextOfferClaim::for_key(CONNECTION_ROLE, FactScope::Local, connection_id)
}

/// Projector route metadata for the connection fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("connection::connection::project::ConnectionProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

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
            authenticate::Authentication::NeedsContext(needs) => {
                let output = needs
                    .into_iter()
                    .fold(ProjectionOutput::new(), |output, need| output.need(need));
                attach_connection_observation_if_available(fact, context, output)
            }
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
                .row_mutation(RowMutation::DeleteWhere(
                    CONNECTION_TABLE.delete_by_key(vec![Value::Bytes(fact.id.to_vec())]),
                ))
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
                    .offer(request::project::connection_for_request_offer_claim(
                        connection.request_id,
                    ))
                    .intent(seed_connection_sync_intent(SeedConnectionSync {
                        connection_id: fact.id,
                    }))
                    .local_intent(queue_outgoing_frame_intent(QueueOutgoingFrame {
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
    let observation = connection_observation(fact, context)?;
    let (observation_output, observed) = match observation {
        ObservationResolution::Observed { output, origin } => (output, origin),
        ObservationResolution::Missing { output: next } => {
            return Ok(merge_projection_output(
                needs.apply_to(ProjectionOutput::new()),
                next,
            ));
        }
    };
    let output = merge_projection_output(
        needs.apply_to(materialized_output(fact, connection)),
        observation_output,
    );
    let receipt = connection_fact_receipt_for_path(ReceiptPathInput {
        received_fact_id: fact.id,
        origin_addr: &observed.origin_addr,
        local_endpoint_id: connection.to_endpoint,
        sender_endpoint_id: connection.from_endpoint,
        receive_path: RECEIVE_PATH_CONNECTION,
        connection_id: Some(fact.id),
        request_id: Some(connection.request_id),
        frame_hash: crypto::hash(fact.body()),
        received_at_local_ms: observed.received_at_local_ms,
    })?;
    Ok(output
        .fact(receipt)
        .intent(seed_connection_sync_intent(SeedConnectionSync {
            connection_id: fact.id,
        })))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedOrigin {
    origin_addr: Vec<u8>,
    received_at_local_ms: u64,
}

enum ObservationResolution {
    Observed {
        output: ProjectionOutput,
        origin: ObservedOrigin,
    },
    Missing {
        output: ProjectionOutput,
    },
}

fn attach_connection_observation_if_available(
    fact: &Fact,
    context: &ProjectionContext,
    output: ProjectionOutput,
) -> Result<ProjectionOutput, String> {
    let need = frame_observation::project::connection_frame_observation_need(fact.id, fact.id);
    if context.incoming_metadata().is_none() && context.offer_for(&need).is_none() {
        return Ok(output);
    }
    let observation = connection_observation(fact, context)?;
    let addition = match observation {
        ObservationResolution::Observed { output, .. }
        | ObservationResolution::Missing { output } => output,
    };
    Ok(merge_projection_output(output, addition))
}

fn connection_observation(
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<ObservationResolution, String> {
    let need = frame_observation::project::connection_frame_observation_need(fact.id, fact.id);
    let output = ProjectionOutput::new().need(need.clone());
    if let Some(metadata) = context.incoming_metadata() {
        let observation = frame_observation::project::connection_frame_observation_fact(
            fact.id,
            &metadata.origin_addr,
            metadata.received_at_local_ms,
        )?;
        return Ok(ObservationResolution::Observed {
            output: output.fact(observation),
            origin: ObservedOrigin {
                origin_addr: metadata.origin_addr.clone(),
                received_at_local_ms: metadata.received_at_local_ms,
            },
        });
    }

    let Some(observation_fact) = context.payload_for(&need) else {
        return Ok(ObservationResolution::Missing { output });
    };
    if observation_fact.scope != FactScope::Local {
        return Err("connection observation context must be local".to_string());
    }
    let observed = frame_observation::project::decode::decode_fact(observation_fact.body())
        .map_err(|_| "connection observation context is malformed".to_string())?;
    if observed.frame_fact_id != fact.id {
        return Err("connection observation does not bind connection".to_string());
    }
    Ok(ObservationResolution::Observed {
        output,
        origin: ObservedOrigin {
            origin_addr: observed.origin_addr.bytes().to_vec(),
            received_at_local_ms: observed.received_at_local_ms,
        },
    })
}

fn merge_projection_output(
    mut output: ProjectionOutput,
    addition: ProjectionOutput,
) -> ProjectionOutput {
    output.needs.extend(addition.needs);
    output.offers.extend(addition.offers);
    output.time_wakes.extend(addition.time_wakes);
    output.effects.facts.extend(addition.effects.facts);
    output
}

fn materialized_output(fact: &Fact, connection: &ConnectionFact) -> ProjectionOutput {
    ProjectionOutput::new()
        .offer(connection_offer_claim(fact.id))
        .row_mutation(RowMutation::InsertValues(
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

#[derive(Debug, Clone)]
struct ConnectionNeeds {
    close: ContextNeed,
    request: ContextNeed,
    request_opener: ContextNeed,
    responder_secret: Option<ContextNeed>,
    endpoint: Option<ContextNeed>,
    initiator: Option<ContextNeed>,
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
            invite,
        }
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

// Tests. Ordered most-central-first: full materialize paths lead, then context-park gates, then replay/edge guards.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::project_fact::{IncomingMetadata, MatchedContext, ProjectionMode};
    use crate::protocol::connection::queue_outgoing_frame::QUEUE_OUTGOING_FRAME;
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

    fn initiator_semantic(fact_id: FactId, connection: ConnectionFact) -> AuthenticatedConnection {
        AuthenticatedConnection::Initiator {
            request_need: request::project::connection_request_need(fact_id, connection.request_id),
            request_opener_need: authenticate::ephemeral_secret_public_key_need(fact_id, [10; 32]),
            endpoint_need: authenticate::local_endpoint_need(fact_id, connection.to_endpoint),
            initiator_need: authenticate::exact_need(
                fact_id,
                "connection_ephemeral_secret",
                FactScope::Local,
                connection.initiator_ephemeral_secret_fact_id,
            ),
            invite_need: None,
            connection,
        }
    }

    fn frame_observation_match(
        owner: FactId,
        origin_addr: &[u8],
        received_at: u64,
    ) -> MatchedContext {
        let need = frame_observation::project::connection_frame_observation_need(owner, owner);
        let observation = frame_observation::project::connection_frame_observation_fact(
            owner,
            origin_addr,
            received_at,
        )
        .expect("connection observation fact");
        MatchedContext {
            need,
            offer: frame_observation::project::connection_frame_observation_offer(
                observation.id,
                owner,
            ),
            payload: observation,
        }
    }

    #[test]
    fn initiator_projection_uses_durable_observation_for_receipt() {
        let fact = Fact::new(FactScope::Local, 10, vec![49, 1, 2, 3]);
        let origin = b"127.0.0.1:41044";
        let received_at = 1_700_000_444;
        let connection = connection_fact();
        let context = ProjectionContext::from_matches(vec![frame_observation_match(
            fact.id,
            origin,
            received_at,
        )]);

        let output = ConnectionProjector::new()
            .project_semantic(
                &fact,
                initiator_semantic(fact.id, connection.clone()),
                &context,
            )
            .expect("project initiator connection");

        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == "connection"));
        assert_eq!(output.effects.facts.len(), 1);
        let receipt = crate::protocol::connection::fact_receipt::project::decode::decode_fact(
            output.effects.facts[0].body(),
        )
        .expect("decode receipt");
        assert_eq!(receipt.received_fact_id, fact.id);
        assert_eq!(receipt.origin_addr.bytes(), origin);
        assert_eq!(receipt.local_endpoint_id, connection.to_endpoint);
        assert_eq!(receipt.sender_endpoint_id, connection.from_endpoint);
        assert_eq!(receipt.connection_id, Some(fact.id));
        assert_eq!(receipt.request_id, Some(connection.request_id));
        assert_eq!(receipt.received_at_local_ms, received_at);
    }

    #[test]
    fn initiator_projection_records_observation_from_incoming_metadata() {
        let fact = Fact::new(FactScope::Local, 10, vec![49, 1, 2, 3]);
        let owner_id = fact.id;
        let origin = b"127.0.0.1:41055";
        let received_at = 1_700_000_555;
        let context = ProjectionContext::default().with_incoming_metadata(IncomingMetadata {
            origin_addr: origin.to_vec(),
            received_at_local_ms: received_at,
        });

        let output = ConnectionProjector::new()
            .project_semantic(
                &fact,
                initiator_semantic(fact.id, connection_fact()),
                &context,
            )
            .expect("project initiator connection");

        assert_eq!(output.effects.facts.len(), 2);
        assert!(output.effects.facts.iter().any(|emitted| {
            frame_observation::project::decode::decode_fact(emitted.body())
                .map(|observed| {
                    observed.frame_fact_id == owner_id
                        && observed.origin_addr.bytes() == origin
                        && observed.received_at_local_ms == received_at
                })
                .unwrap_or(false)
        }));
        assert!(output.effects.facts.iter().any(|emitted| {
            crate::protocol::connection::fact_receipt::project::decode::decode_fact(emitted.body())
                .map(|receipt| {
                    receipt.received_fact_id == owner_id
                        && receipt.origin_addr.bytes() == origin
                        && receipt.received_at_local_ms == received_at
                })
                .unwrap_or(false)
        }));
    }

    #[test]
    fn responder_projection_sends_response_and_seeds_sync() {
        let fact = Fact::new(FactScope::Local, 10, vec![49, 1, 2, 3]);
        let connection = connection_fact();
        let request_need = request::project::connection_request_need(fact.id, [3; 32]);
        let request_opener_need =
            authenticate::local_endpoint_need(fact.id, connection.from_endpoint);
        let responder_secret_need = authenticate::ephemeral_secret_public_key_need(
            fact.id,
            connection.responder_ephemeral_public_key,
        );
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
                    connection,
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
            .any(|intent| intent.kind.as_str() == QUEUE_OUTGOING_FRAME));
    }

    #[test]
    fn initiator_projection_parks_without_origin_observation() {
        let fact = Fact::new(FactScope::Local, 10, vec![49, 1, 2, 3]);
        let output = ConnectionProjector::new()
            .project_semantic(
                &fact,
                initiator_semantic(fact.id, connection_fact()),
                &ProjectionContext::default(),
            )
            .expect("project initiator connection");

        assert!(output
            .needs
            .iter()
            .any(|need| need.role.as_str() == "connection_frame_observation"));
        assert!(output.offers.is_empty());
        assert!(output.effects.is_empty());
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
                    request_opener_need: authenticate::local_endpoint_need(fact.id, [1; 32]),
                    responder_secret_need: authenticate::ephemeral_secret_public_key_need(
                        fact.id, [6; 32],
                    ),
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
