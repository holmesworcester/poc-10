pub mod decode {
    //! Byte decoding for unified connection-request facts.
    //!
    //! Decoding proves only the fixed plaintext layout and the canonical sealed
    //! envelope shape (tag, version, length, header fields). Helpers here can open
    //! sealed bytes once a caller has side-specific ephemeral/endpoint context; the
    //! id check, opening decision, and request signature proof live in
    //! the local `authenticate` module.

    use crate::core::crypto::{self, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES};
    use crate::core::wire;
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;

    use super::super::encode::{
        self, ADDR_BLOCK_BYTES, PLAINTEXT_FACT_BYTES, REQUEST_PURPOSE, SEALED_FACT_BYTES,
        SEALED_HEADER_BYTES, SEAL_VERSION, TYPE_CONNECTION_REQUEST,
    };
    use super::super::fact::ConnectionRequestFact;

    /// Sealed connection-request envelope codec.
    ///
    /// Decoding a connection request proves only the canonical sealed layout (tag,
    /// length, header fields). The id check, opening decision, and request
    /// signature proof are the local `authenticate` module work, so the decoded payload is the
    /// unit envelope.
    pub fn decode_optional_addr(
        bytes: &[u8; ADDR_BLOCK_BYTES],
    ) -> Result<Option<super::super::fact::ConnectionAddr>, String> {
        encode::decode_optional_addr(bytes)
    }

    pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionRequestFact, String> {
        decode_plaintext(bytes)
    }

    pub fn decode_plaintext(bytes: &[u8]) -> Result<ConnectionRequestFact, String> {
        wire::expect_len(bytes, PLAINTEXT_FACT_BYTES).map_err(wire_err)?;
        if bytes[0] != TYPE_CONNECTION_REQUEST {
            return Err("expected connection request fact".to_string());
        }
        let mode = bytes[1];
        let mut from_endpoint = [0; 32];
        from_endpoint.copy_from_slice(&bytes[2..34]);
        let mut to_endpoint = [0; 32];
        to_endpoint.copy_from_slice(&bytes[34..66]);
        let mut nonce = [0; 32];
        nonce.copy_from_slice(&bytes[66..98]);
        let mut cursor = 98;
        let mut addr_bytes = [0u8; ADDR_BLOCK_BYTES];
        addr_bytes.copy_from_slice(&bytes[cursor..cursor + ADDR_BLOCK_BYTES]);
        let dialed_addr = decode_optional_addr(&addr_bytes)?;
        cursor += ADDR_BLOCK_BYTES;
        addr_bytes.copy_from_slice(&bytes[cursor..cursor + ADDR_BLOCK_BYTES]);
        let initiator_addr = decode_optional_addr(&addr_bytes)?;
        cursor += ADDR_BLOCK_BYTES;
        let mut invite_fact_id = [0; 32];
        invite_fact_id.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        let mut bootstrap_hash = [0; 32];
        bootstrap_hash.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        let mut invite_secret_fact_id = [0; 32];
        invite_secret_fact_id.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        let mut invite_signature = [0; crypto::ED25519_SIGNATURE_BYTES];
        invite_signature.copy_from_slice(&bytes[cursor..cursor + crypto::ED25519_SIGNATURE_BYTES]);
        cursor += crypto::ED25519_SIGNATURE_BYTES;
        let mut initiator_endpoint_shared_id = [0; 32];
        initiator_endpoint_shared_id.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        let mut endpoint_signature = [0; crypto::ED25519_SIGNATURE_BYTES];
        endpoint_signature
            .copy_from_slice(&bytes[cursor..cursor + crypto::ED25519_SIGNATURE_BYTES]);
        cursor += crypto::ED25519_SIGNATURE_BYTES;
        let mut initiator_ephemeral_secret_fact_id = [0; 32];
        initiator_ephemeral_secret_fact_id.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        let mut initiator_ephemeral_public_key = [0; 32];
        initiator_ephemeral_public_key.copy_from_slice(&bytes[cursor..cursor + 32]);
        Ok(ConnectionRequestFact {
            mode,
            from_endpoint,
            to_endpoint,
            nonce,
            dialed_addr,
            initiator_addr,
            invite_fact_id,
            bootstrap_hash,
            invite_secret_fact_id,
            invite_signature,
            initiator_endpoint_shared_id,
            endpoint_signature,
            initiator_ephemeral_secret_fact_id,
            initiator_ephemeral_public_key,
        })
    }

    pub fn is_sealed_fact(bytes: &[u8]) -> bool {
        bytes.first().copied() == Some(TYPE_CONNECTION_REQUEST) && bytes.len() == SEALED_FACT_BYTES
    }

    pub fn open_fact(
        bytes: &[u8],
        local_endpoint: &EndpointFact,
    ) -> Result<ConnectionRequestFact, String> {
        let plaintext = open_fact_bytes(bytes, local_endpoint)?;
        decode_plaintext(&plaintext)
    }

    pub fn open_fact_bytes(bytes: &[u8], local_endpoint: &EndpointFact) -> Result<Vec<u8>, String> {
        validate_sealed_fact(bytes)?;
        let initiator_ephemeral_public_key = request_header_ephemeral_public_key(bytes)?;
        let to_endpoint = request_header_to_endpoint(bytes)?;
        let nonce = nonce_from(&bytes[66..90]);
        let header = &bytes[..SEALED_HEADER_BYTES];
        let ciphertext = &bytes[SEALED_HEADER_BYTES..];
        let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
            &local_endpoint.secret,
            &initiator_ephemeral_public_key,
            REQUEST_PURPOSE,
            header,
            &nonce,
            ciphertext,
        )?;
        let request = decode_plaintext(&plaintext)?;
        if request.to_endpoint != local_endpoint.endpoint || request.to_endpoint != to_endpoint {
            return Err("sealed connection request is addressed to another endpoint".to_string());
        }
        if request.initiator_ephemeral_public_key != initiator_ephemeral_public_key {
            return Err(
                "sealed connection request inner ephemeral key does not match header".to_string(),
            );
        }
        Ok(plaintext)
    }

    pub fn open_fact_as_sender(
        bytes: &[u8],
        initiator_ephemeral: &ConnectionEphemeralSecretFact,
    ) -> Result<ConnectionRequestFact, String> {
        let plaintext = open_fact_bytes_as_sender(bytes, initiator_ephemeral)?;
        decode_plaintext(&plaintext)
    }

    pub fn open_fact_bytes_as_sender(
        bytes: &[u8],
        initiator_ephemeral: &ConnectionEphemeralSecretFact,
    ) -> Result<Vec<u8>, String> {
        validate_sealed_fact(bytes)?;
        let initiator_ephemeral_public_key = request_header_ephemeral_public_key(bytes)?;
        if initiator_ephemeral.ephemeral_public_key != initiator_ephemeral_public_key {
            return Err(
                "sealed connection request sender ephemeral key does not match header".to_string(),
            );
        }
        let to_endpoint = request_header_to_endpoint(bytes)?;
        let nonce = nonce_from(&bytes[66..90]);
        let header = &bytes[..SEALED_HEADER_BYTES];
        let ciphertext = &bytes[SEALED_HEADER_BYTES..];
        let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
            &initiator_ephemeral.ephemeral_private_key,
            &to_endpoint,
            REQUEST_PURPOSE,
            header,
            &nonce,
            ciphertext,
        )?;
        let request = decode_plaintext(&plaintext)?;
        if request.to_endpoint != to_endpoint {
            return Err(
                "sealed connection request inner endpoint does not match header".to_string(),
            );
        }
        if request.from_endpoint != initiator_ephemeral.owner_endpoint {
            return Err("sealed connection request sender does not own request".to_string());
        }
        if request.initiator_ephemeral_public_key != initiator_ephemeral.ephemeral_public_key {
            return Err(
                "sealed connection request inner ephemeral key does not match sender".to_string(),
            );
        }
        Ok(plaintext)
    }

    pub fn request_header_ephemeral_public_key(bytes: &[u8]) -> Result<[u8; 32], String> {
        validate_sealed_fact(bytes)?;
        let mut key = [0; 32];
        key.copy_from_slice(&bytes[2..34]);
        Ok(key)
    }

    pub fn request_header_to_endpoint(bytes: &[u8]) -> Result<[u8; 32], String> {
        validate_sealed_fact(bytes)?;
        let mut key = [0; 32];
        key.copy_from_slice(&bytes[34..66]);
        Ok(key)
    }

    pub fn validate_sealed_fact(bytes: &[u8]) -> Result<(), String> {
        if bytes.len() != SEALED_FACT_BYTES {
            return Err("sealed connection request has wrong length".to_string());
        }
        if bytes[0] != TYPE_CONNECTION_REQUEST || bytes[1] != SEAL_VERSION {
            return Err("sealed connection request has unsupported header".to_string());
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
        use crate::core::crypto::ED25519_SIGNATURE_BYTES;
        use crate::protocol::connection::request::encode::{
            encode_fact, PLAINTEXT_FACT_BYTES, TYPE_CONNECTION_REQUEST,
        };
        use crate::protocol::connection::request::fact::{
            REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP,
        };

        use super::*;

        fn fact(mode: u8) -> ConnectionRequestFact {
            ConnectionRequestFact {
                mode,
                from_endpoint: [1; 32],
                to_endpoint: [2; 32],
                nonce: [3; 32],
                dialed_addr: Some("127.0.0.1:41001".parse().unwrap()),
                initiator_addr: Some("127.0.0.1:41000".parse().unwrap()),
                invite_fact_id: if mode == REQUEST_MODE_BOOTSTRAP {
                    [4; 32]
                } else {
                    [0; 32]
                },
                bootstrap_hash: if mode == REQUEST_MODE_BOOTSTRAP {
                    [5; 32]
                } else {
                    [0; 32]
                },
                invite_secret_fact_id: if mode == REQUEST_MODE_BOOTSTRAP {
                    [6; 32]
                } else {
                    [0; 32]
                },
                invite_signature: if mode == REQUEST_MODE_BOOTSTRAP {
                    [7; ED25519_SIGNATURE_BYTES]
                } else {
                    [0; ED25519_SIGNATURE_BYTES]
                },
                initiator_endpoint_shared_id: if mode == REQUEST_MODE_MEMBERSHIP {
                    [8; 32]
                } else {
                    [0; 32]
                },
                endpoint_signature: if mode == REQUEST_MODE_MEMBERSHIP {
                    [9; ED25519_SIGNATURE_BYTES]
                } else {
                    [0; ED25519_SIGNATURE_BYTES]
                },
                initiator_ephemeral_secret_fact_id: [10; 32],
                initiator_ephemeral_public_key: [11; 32],
            }
        }

        #[test]
        fn connection_request_roundtrips_fixed_width() {
            for mode in [REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP] {
                let bytes = encode_fact(&fact(mode)).expect("encode");
                assert_eq!(bytes.len(), PLAINTEXT_FACT_BYTES);
                assert_eq!(decode_fact(&bytes).expect("decode"), fact(mode));
            }
        }

        #[test]
        fn rejects_wrong_tag_or_length() {
            let mut bytes = encode_fact(&fact(REQUEST_MODE_MEMBERSHIP)).expect("encode");
            bytes[0] = TYPE_CONNECTION_REQUEST.wrapping_add(1);
            assert!(decode_fact(&bytes).is_err());

            let mut short = encode_fact(&fact(REQUEST_MODE_MEMBERSHIP)).expect("encode");
            short.pop();
            assert!(decode_fact(&short).is_err());
        }
    }
}
pub mod authenticate {
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
    use crate::core::crypto::{self, Ed25519PublicKey};
    use crate::core::facts::{Fact, FactId, FactScope};
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};
    use crate::protocol::auth::{endpoint, endpoint_shared, invite_accepted, invite_secret};
    use crate::protocol::connection::ephemeral_secret;

    use super::super::encode;
    use super::super::fact::{
        ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP,
    };
    use super::decode;

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

    pub(crate) enum Authentication {
        Authenticated(AuthenticatedConnectionRequest),
        NeedsContext(Vec<ContextNeed>),
    }

    pub(crate) fn authenticate(
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<Authentication, String> {
        if let Err(error) = verify_fact_id(fact) {
            return Err(error);
        }

        let sender_need = ephemeral_secret_public_key_need(
            fact.id,
            decode::request_header_ephemeral_public_key(fact.body())?,
        );
        for (_, secret_fact) in context.matched_payloads_for(&sender_need) {
            if secret_fact.scope != FactScope::Local {
                return Err("connection request sender secret context must be local".to_string());
            }
            let secret =
                match ephemeral_secret::decode_fact_payload(secret_fact.body()).map_err(|_| {
                    "connection request sender context is not an ephemeral secret".to_string()
                }) {
                    Ok(secret) => secret,
                    Err(error) => return Err(error),
                };
            let Ok(request) = decode::open_fact_as_sender(fact.body(), &secret) else {
                continue;
            };
            if let Err(error) = validate_common_request(fact.id, &request) {
                return Err(error);
            }
            if request.initiator_ephemeral_secret_fact_id != secret_fact.id {
                return Err(
                    "connection request sender secret id does not match request".to_string()
                );
            }
            match authenticate_request_signature(fact.id, &request, context) {
                Ok(Some(needs)) => {
                    return Ok(Authentication::NeedsContext(
                        [sender_need.clone()].into_iter().chain(needs).collect(),
                    ));
                }
                Ok(None) => {
                    return Ok(Authentication::Authenticated(
                        AuthenticatedConnectionRequest::Sender {
                            request,
                            base_need: sender_need.clone(),
                        },
                    ));
                }
                Err(error) => return Err(error),
            }
        }

        let receiver_need =
            local_endpoint_need(fact.id, decode::request_header_to_endpoint(fact.body())?);
        for (_, endpoint_fact) in context.matched_payloads_for(&receiver_need) {
            if endpoint_fact.scope != FactScope::Local {
                return Err(
                    "connection request receiver endpoint context must be local".to_string()
                );
            }
            let local_endpoint =
                match endpoint::decode_fact_payload(endpoint_fact.body()).map_err(|_| {
                    "connection request receiver context is not a local endpoint".to_string()
                }) {
                    Ok(endpoint) => endpoint,
                    Err(error) => return Err(error),
                };
            let Ok(request) = decode::open_fact(fact.body(), &local_endpoint) else {
                continue;
            };
            if let Err(error) = validate_common_request(fact.id, &request) {
                return Err(error);
            }
            match authenticate_request_signature(fact.id, &request, context) {
                Ok(Some(needs)) => {
                    return Ok(Authentication::NeedsContext(
                        [receiver_need.clone()].into_iter().chain(needs).collect(),
                    ));
                }
                Ok(None) => {
                    return Ok(Authentication::Authenticated(
                        AuthenticatedConnectionRequest::Receiver {
                            request,
                            base_need: receiver_need.clone(),
                        },
                    ));
                }
                Err(error) => return Err(error),
            }
        }

        Ok(Authentication::NeedsContext(vec![
            sender_need,
            receiver_need,
        ]))
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
                let invite =
                    invite_secret_from_context_fact(invite_fact, request.invite_secret_fact_id)
                        .map_err(|_| {
                            "connection request invite context is malformed".to_string()
                        })?;
                validate_invite_signature(request, &invite)?;
                Ok(None)
            }
            REQUEST_MODE_MEMBERSHIP => {
                let shared_need = endpoint_shared_need(owner, request.initiator_endpoint_shared_id);
                let Some(shared_fact) = context.payload_for(&shared_need) else {
                    return Ok(Some(vec![shared_need]));
                };
                if shared_fact.scope != FactScope::Global {
                    return Err(
                        "connection request endpoint_shared context must be global".to_string()
                    );
                }
                let shared =
                    endpoint_shared::decode_fact_payload(shared_fact.body()).map_err(|_| {
                        "connection request endpoint_shared context is malformed".to_string()
                    })?;
                if shared.endpoint_id != request.from_endpoint {
                    return Err(
                        "connection request endpoint_shared does not bind sender".to_string()
                    );
                }
                validate_endpoint_signature(request, &shared.signing_public_key)?;
                Ok(None)
            }
            _ => unreachable!("validated request mode"),
        }
    }

    pub(crate) fn validate_invite_signature(
        request: &ConnectionRequestFact,
        invite_secret: &invite_secret::fact::InviteSecretFact,
    ) -> Result<(), String> {
        if request.mode != REQUEST_MODE_BOOTSTRAP {
            return Err("connection request invite validation requires bootstrap mode".to_string());
        }
        if invite_secret.bootstrap_hash != request.bootstrap_hash {
            return Err("connection request bootstrap hash is not authorized".to_string());
        }
        if let Some(invite_fact_id) = invite_secret.invite_fact_id {
            if invite_fact_id != request.invite_fact_id {
                return Err("connection request invite id is not authorized".to_string());
            }
        }
        let public_key = crypto::ed25519_public_key(&invite_secret.bootstrap_secret);
        if !crypto::ed25519_verify(
            &public_key,
            &encode::bootstrap_signature_bytes(request)?,
            &request.invite_signature,
        ) {
            return Err("connection request invite signature is not authorized".to_string());
        }
        Ok(())
    }

    pub(crate) fn invite_secret_from_context_fact(
        fact: &Fact,
        expected_invite_secret_id: FactId,
    ) -> Result<invite_secret::fact::InviteSecretFact, String> {
        if let Ok(secret) = invite_secret::decode_fact_payload(fact.body()) {
            if fact.id != expected_invite_secret_id {
                return Err("connection invite context id does not match request".to_string());
            }
            return Ok(secret);
        }
        let accepted = invite_accepted::decode_fact_payload(fact.body())
            .map_err(|_| "connection invite context is not invite_secret or invite_accepted")?;
        let derived_id = invite_accepted::derived_invite_secret_fact_id(&accepted)?;
        if derived_id != expected_invite_secret_id {
            return Err(
                "connection invite_accepted context does not derive request secret id".into(),
            );
        }
        Ok(invite_accepted::derived_invite_secret(&accepted))
    }

    pub(crate) fn validate_invite_context_scope(fact: &Fact) -> Result<(), String> {
        if fact.scope != FactScope::Local {
            return Err("connection request invite context must be local".to_string());
        }
        Ok(())
    }

    pub(crate) fn validate_endpoint_shared_context_scope(fact: &Fact) -> Result<(), String> {
        if fact.scope != FactScope::Global {
            return Err("connection request endpoint_shared context must be global".to_string());
        }
        Ok(())
    }

    pub(crate) fn validate_endpoint_signature(
        request: &ConnectionRequestFact,
        signing_public_key: &Ed25519PublicKey,
    ) -> Result<(), String> {
        if request.mode != REQUEST_MODE_MEMBERSHIP {
            return Err(
                "connection request endpoint validation requires membership mode".to_string(),
            );
        }
        if !crypto::ed25519_verify(
            signing_public_key,
            &encode::endpoint_signature_bytes(request)?,
            &request.endpoint_signature,
        ) {
            return Err("connection request endpoint signature is not authorized".to_string());
        }
        Ok(())
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
        validate_mode_shape(request)
    }

    pub(crate) fn validate_mode_shape(request: &ConnectionRequestFact) -> Result<(), String> {
        match request.mode {
            REQUEST_MODE_BOOTSTRAP => {
                require_nonzero("invite_fact_id", &request.invite_fact_id)?;
                require_nonzero("bootstrap_hash", &request.bootstrap_hash)?;
                require_nonzero("invite_secret_fact_id", &request.invite_secret_fact_id)?;
                if request.invite_signature == [0; crypto::ED25519_SIGNATURE_BYTES] {
                    return Err("bootstrap request invite_signature cannot be empty".to_string());
                }
                require_zero(
                    "initiator_endpoint_shared_id",
                    &request.initiator_endpoint_shared_id,
                )?;
                if request.endpoint_signature != [0; crypto::ED25519_SIGNATURE_BYTES] {
                    return Err("bootstrap request endpoint_signature must be zero".to_string());
                }
            }
            REQUEST_MODE_MEMBERSHIP => {
                require_zero("invite_fact_id", &request.invite_fact_id)?;
                require_zero("bootstrap_hash", &request.bootstrap_hash)?;
                require_zero("invite_secret_fact_id", &request.invite_secret_fact_id)?;
                if request.invite_signature != [0; crypto::ED25519_SIGNATURE_BYTES] {
                    return Err("membership request invite_signature must be zero".to_string());
                }
                require_nonzero(
                    "initiator_endpoint_shared_id",
                    &request.initiator_endpoint_shared_id,
                )?;
                if request.endpoint_signature == [0; crypto::ED25519_SIGNATURE_BYTES] {
                    return Err("membership request endpoint_signature cannot be empty".to_string());
                }
            }
            other => return Err(format!("unknown connection request mode {other}")),
        }
        Ok(())
    }

    fn require_nonzero(name: &str, value: &[u8; 32]) -> Result<(), String> {
        if value == &[0; 32] {
            Err(format!("connection request {name} cannot be empty"))
        } else {
            Ok(())
        }
    }

    fn require_zero(name: &str, value: &[u8; 32]) -> Result<(), String> {
        if value != &[0; 32] {
            Err(format!("connection request inactive {name} must be zero"))
        } else {
            Ok(())
        }
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
        ContextNeed::for_key(owner, role, scope, key)
    }

    // Tests. Ordered most-central-first: canonical happy path leads, then rejection guards.
    #[cfg(test)]
    mod tests {
        use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
        use crate::core::facts::{Fact, FactScope};
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::endpoint::fact::EndpointFact;
        use crate::protocol::connection::request::encode;
        use crate::protocol::connection::request::fact::{
            ConnectionRequestFact, REQUEST_MODE_MEMBERSHIP,
        };

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
            sign_membership_request_for_test(&mut request, &endpoint);
            let bytes = encode::seal_fact(&request, &initiator_ephemeral_private_key)
                .expect("seal connection_request fact");
            Fact::new(FactScope::Global, 100, bytes)
        }

        fn sign_membership_request_for_test(
            request: &mut ConnectionRequestFact,
            endpoint: &EndpointFact,
        ) {
            request.endpoint_signature = crypto::ed25519_sign(
                &endpoint.signing_secret,
                &encode::endpoint_signature_bytes(request).expect("signature bytes"),
            );
        }

        fn authenticate(fact: &Fact) -> Result<super::Authentication, String> {
            super::super::decode::validate_sealed_fact(fact.body())?;
            super::authenticate(fact, &ProjectionContext::default())
        }

        fn is_invalid(fact: &Fact) -> bool {
            authenticate(fact).is_err()
        }

        // The membership signing key is not embedded in the request — it lives in the
        // initiator's endpoint_shared — so a well-formed canonical request parks on
        // that context rather than authenticating outright. We assert it is NOT
        // Invalid; the signature itself is proven once context lands.
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
    //! Connection-request semantic adapter.
    //!
    //! The authenticated opened request is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::authenticate::AuthenticatedConnectionRequest;

    pub(crate) fn adapt(
        source: AuthenticatedConnectionRequest,
    ) -> Result<AuthenticatedConnectionRequest, String> {
        Ok(source)
    }
}

// Unified connection-request projector.
//
// The same sealed request fact is projected on both sides after
// the local `authenticate` module has opened it with local sender/receiver context and
// verified the bootstrap or membership signature. The initiator branch
// materializes retryable send state. The responder branch records the receive
// receipt and schedules `create_connection`. During replay this live
// negotiation state is intentionally not rebuilt; the retained fact remains
// evidence, but the projector returns no effects.
//
// POLICY. A connection_request is admitted iff:
//   1. STRUCTURAL. The fact is global; primary byte shape, id, opening, and
//      request signature have already been authenticated.
//   2. CONTEXT. The initiator branch requires invite or endpoint_shared
//      authority; the responder branch requires receive observation and
//      matching authority context.
//   3. MATERIALIZE. Initiators write retryable request send state; responders
//      emit a receipt and the deterministic create_connection intent.

use crate::core::context::{ContextNeed, ContextOffer, ContextOfferClaim};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectedRowMutation, ProjectionContext, ProjectionOutput, Projector,
};

use crate::protocol::auth::{endpoint_shared, workspace};
use crate::protocol::connection::create_connection::{create_connection_intent, CreateConnection};
use crate::protocol::connection::fact_receipt::fact::ReceiptPathInput;
use crate::protocol::connection::fact_receipt::project::connection_fact_receipt_for_path;
use crate::protocol::connection::frame_observation;

use super::connection_request_row;
use super::fact::{ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP};
use authenticate::AuthenticatedConnectionRequest;

const CONNECTION_REQUEST_ROLE: &str = "connection_request";
const CONNECTION_FOR_REQUEST_ROLE: &str = "connection_for_request";

pub fn connection_request_need(owner: FactId, request_id: FactId) -> ContextNeed {
    ContextNeed::for_key(
        owner,
        CONNECTION_REQUEST_ROLE,
        FactScope::Global,
        request_id,
    )
}

pub fn connection_request_offer(owner: FactId, request_id: FactId) -> ContextOffer {
    ContextOffer::for_key(
        owner,
        CONNECTION_REQUEST_ROLE,
        FactScope::Global,
        request_id,
    )
}

pub fn connection_request_offer_claim(request_id: FactId) -> ContextOfferClaim {
    ContextOfferClaim::for_key(CONNECTION_REQUEST_ROLE, FactScope::Global, request_id)
}

pub fn connection_for_request_need(owner: FactId, request_id: FactId) -> ContextNeed {
    ContextNeed::for_key(
        owner,
        CONNECTION_FOR_REQUEST_ROLE,
        FactScope::Local,
        request_id,
    )
}

pub fn connection_for_request_offer(owner: FactId, request_id: FactId) -> ContextOffer {
    ContextOffer::for_key(
        owner,
        CONNECTION_FOR_REQUEST_ROLE,
        FactScope::Local,
        request_id,
    )
}

pub fn connection_for_request_offer_claim(request_id: FactId) -> ContextOfferClaim {
    ContextOfferClaim::for_key(CONNECTION_FOR_REQUEST_ROLE, FactScope::Local, request_id)
}

/// Projector route metadata for the connection-request fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("connection::request::project::ConnectionRequestProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct ConnectionRequestProjector;

impl ConnectionRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionRequestProjector {
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
                attach_request_observation_if_available(fact, context, output)
            }
        }
    }
}

impl ConnectionRequestProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        semantic: AuthenticatedConnectionRequest,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("connection request fact must be global".to_string());
        }
        if context.is_replay() {
            return Ok(ProjectionOutput::new());
        }
        // 2-3. Context branch + materialization.
        match semantic {
            AuthenticatedConnectionRequest::Sender { request, base_need } => {
                project_sender_request(fact, &request, context, base_need)
            }
            AuthenticatedConnectionRequest::Receiver { request, base_need } => {
                project_receiver_request(fact, &request, context, base_need)
            }
        }
    }
}

fn project_sender_request(
    fact: &Fact,
    request: &ConnectionRequestFact,
    context: &ProjectionContext,
    base_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let mut output = ProjectionOutput::new().need(base_need);
    match request.mode {
        REQUEST_MODE_BOOTSTRAP => {
            let invite_need = invite_secret_need(fact.id, request.invite_secret_fact_id);
            let Some(invite_fact) = context.payload_for(&invite_need) else {
                return Ok(output.need(invite_need));
            };
            if invite_fact.scope != FactScope::Local {
                return Err("connection request invite context must be local".to_string());
            }
            authenticate::invite_secret_from_context_fact(
                invite_fact,
                request.invite_secret_fact_id,
            )
            .map_err(|_| "connection request invite context is malformed".to_string())?;
            output = output.need(invite_need);
        }
        REQUEST_MODE_MEMBERSHIP => {
            let shared_need = endpoint_shared_need(fact.id, request.initiator_endpoint_shared_id);
            let Some(shared_fact) = context.payload_for(&shared_need) else {
                return Ok(output.need(shared_need));
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
            output = output.need(shared_need);
        }
        _ => unreachable!("validated request mode"),
    }

    let Some(addr) = request.dialed_addr else {
        return Err("connection request dialed_addr is required for sending".to_string());
    };
    Ok(output
        .offer(connection_request_offer_claim(fact.id))
        .row_mutation(ProjectedRowMutation::InsertValues(connection_request_row(
            fact.id,
            fact.id,
            request.initiator_ephemeral_secret_fact_id,
            Some(addr),
            fact.body(),
        )?)))
}

fn project_receiver_request(
    fact: &Fact,
    request: &ConnectionRequestFact,
    context: &ProjectionContext,
    base_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let mut output = ProjectionOutput::new().need(base_need);
    let observed = match request_observation(fact, context)? {
        ObservationResolution::Observed {
            output: next,
            origin,
        } => {
            output = merge_projection_output(output, next);
            Some(origin)
        }
        ObservationResolution::Missing { output: next } => {
            output = merge_projection_output(output, next);
            None
        }
    };
    let authority_id = match request.mode {
        REQUEST_MODE_BOOTSTRAP => {
            let invite_need = invite_secret_need(fact.id, request.invite_secret_fact_id);
            let Some(invite_fact) = context.payload_for(&invite_need) else {
                return Ok(output.need(invite_need));
            };
            if invite_fact.scope != FactScope::Local {
                return Err("connection request invite context must be local".to_string());
            }
            authenticate::invite_secret_from_context_fact(
                invite_fact,
                request.invite_secret_fact_id,
            )
            .map_err(|_| "connection request invite context is malformed".to_string())?;
            output = output.need(invite_need);
            request.invite_secret_fact_id
        }
        REQUEST_MODE_MEMBERSHIP => {
            let shared_need = endpoint_shared_need(fact.id, request.initiator_endpoint_shared_id);
            let Some(shared_fact) = context.payload_for(&shared_need) else {
                return Ok(output.need(shared_need));
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
            let member_need =
                content_signer_need(fact.id, shared.workspace_id, request.to_endpoint);
            let Some(member_fact) = context.payload_for(&member_need) else {
                return Ok(output.need(shared_need).need(member_need));
            };
            let member =
                endpoint_shared::decode_fact_payload(member_fact.body()).map_err(|_| {
                    "connection request mutual membership context is malformed".to_string()
                })?;
            if member.endpoint_id != request.to_endpoint
                || member.workspace_id != shared.workspace_id
            {
                return Err(
                    "connection request mutual membership does not bind receiver".to_string(),
                );
            }
            output = output.need(shared_need).need(member_need);
            request.initiator_endpoint_shared_id
        }
        _ => unreachable!("validated request mode"),
    };

    let Some(observed) = observed else {
        return Ok(output);
    };
    let receipt = connection_fact_receipt_for_path(ReceiptPathInput {
        received_fact_id: fact.id,
        origin_addr: &observed.origin_addr,
        local_endpoint_id: request.to_endpoint,
        sender_endpoint_id: request.from_endpoint,
        receive_path:
            crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_REQUEST,
        connection_id: None,
        request_id: Some(fact.id),
        frame_hash: crypto::hash(fact.body()),
        received_at_local_ms: observed.received_at_local_ms,
    })?;
    let receive_id = receipt.id;
    Ok(output
        .offer(connection_request_offer_claim(fact.id))
        .fact(receipt)
        .intent(create_connection_intent(CreateConnection {
            request_id: fact.id,
            initiator_endpoint_shared_id: authority_id,
            receive_id,
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

fn attach_request_observation_if_available(
    fact: &Fact,
    context: &ProjectionContext,
    output: ProjectionOutput,
) -> Result<ProjectionOutput, String> {
    let need = frame_observation::project::connection_frame_observation_need(fact.id, fact.id);
    if context.incoming_metadata().is_none() && context.offer_for(&need).is_none() {
        return Ok(output);
    }
    let observation = request_observation(fact, context)?;
    let addition = match observation {
        ObservationResolution::Observed { output, .. }
        | ObservationResolution::Missing { output } => output,
    };
    Ok(merge_projection_output(output, addition))
}

fn request_observation(
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
        return Err("connection request observation context must be local".to_string());
    }
    let observed = frame_observation::project::decode::decode_fact(observation_fact.body())
        .map_err(|_| "connection request observation context is malformed".to_string())?;
    if observed.frame_fact_id != fact.id {
        return Err("connection request observation does not bind request".to_string());
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

#[cfg(test)]
fn ephemeral_secret_public_key_need(owner: FactId, public_key: FactId) -> ContextNeed {
    authenticate::ephemeral_secret_public_key_need(owner, public_key)
}

#[cfg(test)]
fn local_endpoint_need(owner: FactId, endpoint_id: FactId) -> ContextNeed {
    authenticate::local_endpoint_need(owner, endpoint_id)
}

fn invite_secret_need(owner: FactId, invite_secret_id: FactId) -> ContextNeed {
    authenticate::invite_secret_need(owner, invite_secret_id)
}

fn endpoint_shared_need(owner: FactId, endpoint_shared_id: FactId) -> ContextNeed {
    authenticate::endpoint_shared_need(owner, endpoint_shared_id)
}

fn content_signer_need(owner: FactId, workspace_id: FactId, endpoint_id: FactId) -> ContextNeed {
    ContextNeed::for_key(
        owner,
        "content_signer",
        workspace::scope(workspace_id),
        endpoint_id,
    )
}

// Tests. Ordered most-central-first: full materialize paths lead, then context-park gates.
#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::project_fact::{
        IncomingMetadata, MatchedContext, ProjectionContext, ProjectionMode, Projector,
    };
    use crate::protocol::auth::endpoint::encode as endpoint_encode;
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::auth::invite_secret::{encode as invite_encode, fact::InviteSecretFact};
    use crate::protocol::connection::ephemeral_secret;
    use crate::protocol::connection::ephemeral_secret::{
        encode as ephemeral_encode, fact::ConnectionEphemeralSecretFact,
    };
    use crate::protocol::connection::request::fact::REQUEST_MODE_BOOTSTRAP;
    use crate::protocol::connection::request::CONNECTION_REQUEST_ROWS;

    use super::super::encode;
    use super::*;

    fn endpoint(secret: [u8; 32], signing_secret: [u8; 32]) -> EndpointFact {
        EndpointFact {
            endpoint: crypto::x25519_public_key(&secret),
            secret,
            signing_public_key: crypto::ed25519_public_key(&signing_secret),
            signing_secret,
        }
    }

    fn bootstrap_facts(local: EndpointFact, remote_endpoint: [u8; 32]) -> (Fact, Fact, Fact) {
        let invite_secret = InviteSecretFact::scoped([5; 32], [6; 32], [7; 32]);
        let invite_fact = Fact::new(
            FactScope::Local,
            10,
            invite_encode::encode_fact(&invite_secret).expect("invite"),
        );
        let ephemeral_private_key = [8; 32];
        let ephemeral = ConnectionEphemeralSecretFact {
            owner_endpoint: local.endpoint,
            ephemeral_private_key,
            ephemeral_public_key: crypto::x25519_public_key(&ephemeral_private_key),
            created_at_ms: 11,
        };
        let ephemeral_fact = Fact::new(
            FactScope::Local,
            11,
            ephemeral_encode::encode_fact(&ephemeral).expect("ephemeral"),
        );
        let mut request = ConnectionRequestFact {
            mode: REQUEST_MODE_BOOTSTRAP,
            from_endpoint: local.endpoint,
            to_endpoint: remote_endpoint,
            nonce: [9; 32],
            dialed_addr: Some("127.0.0.1:41000".parse().unwrap()),
            initiator_addr: Some("127.0.0.1:41010".parse().unwrap()),
            invite_fact_id: [7; 32],
            bootstrap_hash: invite_secret.bootstrap_hash,
            invite_secret_fact_id: invite_fact.id,
            invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
            initiator_endpoint_shared_id: [0; 32],
            endpoint_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
            initiator_ephemeral_secret_fact_id: ephemeral_fact.id,
            initiator_ephemeral_public_key: ephemeral.ephemeral_public_key,
        };
        sign_bootstrap_request_for_test(&mut request, &invite_secret);
        let request_fact = Fact::new(
            FactScope::Global,
            12,
            encode::seal_fact(&request, &ephemeral_private_key).expect("seal request"),
        );
        (invite_fact, ephemeral_fact, request_fact)
    }

    fn sign_bootstrap_request_for_test(
        request: &mut ConnectionRequestFact,
        invite_secret: &InviteSecretFact,
    ) {
        request.invite_signature = crypto::ed25519_sign(
            &invite_secret.bootstrap_secret,
            &encode::bootstrap_signature_bytes(request).expect("signature bytes"),
        );
    }

    fn receiver_context_matches(
        request_fact: &Fact,
        invite_fact: &Fact,
        responder: EndpointFact,
    ) -> Vec<MatchedContext> {
        let endpoint_fact = Fact::new(
            FactScope::Local,
            11,
            endpoint_encode::encode_fact(&responder).expect("endpoint fact"),
        );
        vec![
            MatchedContext {
                need: local_endpoint_need(request_fact.id, responder.endpoint),
                offer: ContextOffer::for_key(
                    endpoint_fact.id,
                    "auth_local_endpoint",
                    FactScope::Local,
                    responder.endpoint,
                ),
                payload: endpoint_fact,
            },
            MatchedContext {
                need: ContextNeed::for_key(
                    request_fact.id,
                    "connection_invite_secret",
                    FactScope::Local,
                    invite_fact.id,
                ),
                offer: ContextOffer::for_key(
                    invite_fact.id,
                    "connection_invite_secret",
                    FactScope::Local,
                    invite_fact.id,
                ),
                payload: invite_fact.clone(),
            },
        ]
    }

    fn request_observation_match(
        request_fact: &Fact,
        metadata: &IncomingMetadata,
    ) -> MatchedContext {
        let observation = frame_observation::project::connection_frame_observation_fact(
            request_fact.id,
            &metadata.origin_addr,
            metadata.received_at_local_ms,
        )
        .expect("request observation fact");
        MatchedContext {
            need: frame_observation::project::connection_frame_observation_need(
                request_fact.id,
                request_fact.id,
            ),
            offer: frame_observation::project::connection_frame_observation_offer(
                observation.id,
                request_fact.id,
            ),
            payload: observation,
        }
    }

    fn assert_exact_need(needs: &[ContextNeed], role: &str, key: FactId) {
        let need = needs
            .iter()
            .find(|need| need.role.as_str() == role)
            .expect("need role");
        assert_eq!(need.start_key.as_bytes(), key);
        assert_eq!(need.end_key.as_bytes(), key);
    }

    #[test]
    fn receiver_request_projection_emits_receipt_and_create_connection_intent() {
        let initiator = endpoint([1; 32], [2; 32]);
        let responder = endpoint([3; 32], [4; 32]);
        let (invite_fact, _, request_fact) = bootstrap_facts(initiator, responder.endpoint);
        let metadata = IncomingMetadata {
            origin_addr: b"127.0.0.1:41010".to_vec(),
            received_at_local_ms: 12,
        };

        let context = ProjectionContext::from_matches(receiver_context_matches(
            &request_fact,
            &invite_fact,
            responder,
        ))
        .with_incoming_metadata(metadata.clone());

        let projected = ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project request");

        assert_eq!(projected.effects.facts.len(), 2);
        assert_eq!(projected.effects.intents.len(), 1);
        let observation = projected
            .effects
            .facts
            .iter()
            .find_map(|fact| frame_observation::project::decode::decode_fact(fact.body()).ok())
            .expect("decode observation");
        assert_eq!(observation.frame_fact_id, request_fact.id);
        assert_eq!(
            observation.origin_addr.bytes(),
            metadata.origin_addr.as_slice()
        );
        let receipt = projected
            .effects
            .facts
            .iter()
            .find_map(|fact| {
                crate::protocol::connection::fact_receipt::project::decode::decode_fact(fact.body())
                    .ok()
            })
            .expect("decode receipt");
        assert_eq!(receipt.origin_addr.bytes(), metadata.origin_addr.as_slice());
        assert_eq!(receipt.received_at_local_ms, metadata.received_at_local_ms);
    }

    #[test]
    fn sender_request_projection_writes_pending_retry_row() {
        let local = endpoint([1; 32], [2; 32]);
        let remote = endpoint([3; 32], [4; 32]);
        let (invite_fact, ephemeral_fact, request_fact) = bootstrap_facts(local, remote.endpoint);

        let context = ProjectionContext::from_matches(vec![
            MatchedContext {
                need: ephemeral_secret_public_key_need(
                    request_fact.id,
                    decode::request_header_ephemeral_public_key(request_fact.body())
                        .expect("request public key"),
                ),
                offer: ContextOffer::for_key(
                    ephemeral_fact.id,
                    ephemeral_secret::project::CONNECTION_EPHEMERAL_SECRET_PUBLIC_KEY_ROLE,
                    FactScope::Local,
                    decode::request_header_ephemeral_public_key(request_fact.body())
                        .expect("request public key"),
                ),
                payload: ephemeral_fact,
            },
            MatchedContext {
                need: ContextNeed::for_key(
                    request_fact.id,
                    "connection_invite_secret",
                    FactScope::Local,
                    invite_fact.id,
                ),
                offer: ContextOffer::for_key(
                    invite_fact.id,
                    "connection_invite_secret",
                    FactScope::Local,
                    invite_fact.id,
                ),
                payload: invite_fact,
            },
        ]);

        let projected = ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project request");

        assert!(projected
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == "connection_request"));
        assert!(projected.row_mutations.iter().any(|mutation| {
            matches!(
                mutation,
                ProjectedRowMutation::InsertValues(insert) if insert.table == CONNECTION_REQUEST_ROWS
            )
        }));

        let replayed = ConnectionRequestProjector::new()
            .project(&request_fact, &context.with_mode(ProjectionMode::Replay))
            .expect("replay request");
        assert!(replayed.offers.is_empty());
        assert!(replayed.needs.is_empty());
        assert!(replayed.effects.facts.is_empty());
        assert!(replayed.row_mutations.is_empty());
        assert!(replayed.effects.intents.is_empty());
    }

    #[test]
    fn receiver_request_projection_uses_durable_observation_for_receipt() {
        let initiator = endpoint([1; 32], [2; 32]);
        let responder = endpoint([3; 32], [4; 32]);
        let (invite_fact, _, request_fact) = bootstrap_facts(initiator, responder.endpoint);
        let metadata = IncomingMetadata {
            origin_addr: b"127.0.0.1:41020".to_vec(),
            received_at_local_ms: 20,
        };
        let mut matches = receiver_context_matches(&request_fact, &invite_fact, responder);
        matches.push(request_observation_match(&request_fact, &metadata));
        let context = ProjectionContext::from_matches(matches);

        let projected = ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project request");

        assert_eq!(projected.effects.facts.len(), 1);
        assert_eq!(projected.effects.intents.len(), 1);
        let receipt = crate::protocol::connection::fact_receipt::project::decode::decode_fact(
            projected.effects.facts[0].body(),
        )
        .expect("decode receipt");
        assert_eq!(receipt.received_fact_id, request_fact.id);
        assert_eq!(receipt.origin_addr.bytes(), metadata.origin_addr.as_slice());
        assert_eq!(receipt.received_at_local_ms, metadata.received_at_local_ms);
    }

    #[test]
    fn incoming_request_records_observation_before_endpoint_context() {
        let initiator = endpoint([1; 32], [2; 32]);
        let responder = endpoint([3; 32], [4; 32]);
        let (_, _, request_fact) = bootstrap_facts(initiator, responder.endpoint);
        let metadata = IncomingMetadata {
            origin_addr: b"127.0.0.1:41030".to_vec(),
            received_at_local_ms: 30,
        };
        let context = ProjectionContext::default().with_incoming_metadata(metadata.clone());

        let projected = ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project request before endpoint context");

        assert!(projected
            .needs
            .iter()
            .any(|need| need.role.as_str() == "auth_local_endpoint"));
        assert!(projected
            .needs
            .iter()
            .any(|need| need.role.as_str() == "connection_frame_observation"));
        assert!(projected.offers.is_empty());
        assert!(projected.effects.intents.is_empty());
        assert_eq!(projected.effects.facts.len(), 1);
        let observation =
            frame_observation::project::decode::decode_fact(projected.effects.facts[0].body())
                .expect("decode observation");
        assert_eq!(observation.frame_fact_id, request_fact.id);
        assert_eq!(
            observation.origin_addr.bytes(),
            metadata.origin_addr.as_slice()
        );
        assert_eq!(
            observation.received_at_local_ms,
            metadata.received_at_local_ms
        );
    }

    #[test]
    fn receiver_request_projection_parks_without_origin_observation() {
        let initiator = endpoint([1; 32], [2; 32]);
        let responder = endpoint([3; 32], [4; 32]);
        let (invite_fact, _, request_fact) = bootstrap_facts(initiator, responder.endpoint);
        let context = ProjectionContext::from_matches(receiver_context_matches(
            &request_fact,
            &invite_fact,
            responder,
        ));

        let projected = ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project request");

        assert!(projected
            .needs
            .iter()
            .any(|need| need.role.as_str() == "connection_frame_observation"));
        assert!(projected.offers.is_empty());
        assert!(projected.effects.is_empty());
    }

    #[test]
    fn missing_request_context_needs_exact_header_keys() {
        let local = endpoint([1; 32], [2; 32]);
        let remote = endpoint([3; 32], [4; 32]);
        let (_, _, request_fact) = bootstrap_facts(local, remote.endpoint);
        let projected = ConnectionRequestProjector::new()
            .project(&request_fact, &ProjectionContext::default())
            .expect("project request without context");

        assert_exact_need(
            &projected.needs,
            ephemeral_secret::project::CONNECTION_EPHEMERAL_SECRET_PUBLIC_KEY_ROLE,
            decode::request_header_ephemeral_public_key(request_fact.body())
                .expect("request public key"),
        );
        assert_exact_need(&projected.needs, "auth_local_endpoint", remote.endpoint);
    }
}
