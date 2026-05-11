//! Projector for inbound transit frames.
//!
//! Transit frames are not semantic facts. They are encrypted transport
//! envelopes around canonical inner event bytes. This projector is the strict
//! admission boundary for those envelopes: it receives one queued core network
//! row plus explicit local context, authenticates and decrypts the frame, and
//! emits `canonical.in` rows carrying the recovered inner bytes and provenance.
//!
//! The important invariant is that this projector never decides what the inner
//! bytes *mean*. It only proves how they arrived:
//!
//! ```text
//! core.network.inbound row
//!   + local endpoint secret
//!   + optional connection -> expected remote endpoint
//!   -> authenticated inner canonical bytes
//!   -> canonical.in rows with transit provenance
//! ```
//!
//! The next admission step classifies those inner bytes under the provenance:
//! endpoint bootstrap may only admit connection requests; invite bootstrap may
//! only admit shared identity facts for the invite workspace; connection transit
//! may admit connection-scoped sync events or shared workspace events after the
//! mutual-endpoint workspace check. That split prevents an adversary from
//! wrapping arbitrary local event bytes and having them projected as if they
//! came from a trusted connection.

use crate::core::crypto;
use crate::core::network_queues::InboundNetworkRow;
use crate::core::store::Store;
use crate::protocol::event_modules::connection::{
    connection_ephemeral, connection_request, connection_response, types::ConnectionId,
};
use crate::protocol::event_modules::identity::endpoint::types::{EndpointId, EndpointKeypair};
use crate::protocol::event_modules::identity::{endpoint, invite};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::ProjectionOutput;
use crate::workers::schema::{self as worker_schema, TransitProvenance, TransitUnwrap};

use super::super::schema as connection_schema;
use super::codec::{self, TransitEnvelopeRef};
use super::types::{BOOTSTRAP_PURPOSE, CONNECTION_PURPOSE, INVITE_BOOTSTRAP_PURPOSE};

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnwrappedTransit {
    inners: Vec<Vec<u8>>,
    unwrapped_with: TransitUnwrap,
    sender_endpoint: EndpointId,
}

/// Project one queued network frame into canonical admission rows.
///
/// `remember_route` is false for daemon accepts because their source ports are
/// usually ephemeral. Tests and future stable-route receive paths can set it
/// when the observed source address is meaningful connection metadata.
pub fn project_network_in(
    store: &Store,
    inbound: &InboundNetworkRow,
    remember_route: bool,
) -> Result<ProjectionOutput, String> {
    let local = local_endpoint(store)?;
    let origin = inbound.source.addr();
    let transit = unwrap(store, local, &inbound.bytes, |connection_id| {
        connection_schema::remote_endpoint(store, *connection_id)
    })?;
    let mut rows = Vec::with_capacity(transit.inners.len());
    for inner in transit.inners {
        let provenance = TransitProvenance {
            origin,
            local_endpoint: local.endpoint,
            sender_endpoint: transit.sender_endpoint,
            remember_route,
            unwrapped_with: transit.unwrapped_with,
        };
        rows.push(worker_schema::transit_canonical_in_row(inner, provenance));
    }
    Ok(ProjectionOutput::rows(rows))
}

/// Load the endpoint secret material needed to decrypt inbound transit.
///
/// Endpoint events/projectors own this fact. Transit projection only reads it as
/// explicit context for the cryptographic boundary.
fn local_endpoint(store: &Store) -> Result<endpoint::types::EndpointKeypair, String> {
    endpoint::commands::local_keypair(store)?.ok_or_else(|| "local endpoint is missing".to_string())
}

fn unwrap(
    store: &Store,
    local: EndpointKeypair,
    bytes: &[u8],
    remote_endpoint: impl FnOnce(&ConnectionId) -> Result<EndpointId, String>,
) -> Result<UnwrappedTransit, String> {
    // The caller supplies remote endpoint lookup for established connections.
    // That keeps storage access outside the cryptographic transform.
    match codec::decode_ref(bytes)? {
        TransitEnvelopeRef::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err("bootstrap transit addressed to a different endpoint".to_string());
            }
            let inner = crypto::x25519_xchacha20poly1305_decrypt(
                &local.secret,
                &sender_endpoint,
                BOOTSTRAP_PURPOSE,
                &codec::associated_data_bootstrap(&sender_endpoint, &recipient_endpoint, &nonce),
                &nonce,
                ciphertext,
            )?;
            Ok(UnwrappedTransit {
                inners: vec![inner],
                unwrapped_with: TransitUnwrap::Bootstrap,
                sender_endpoint,
            })
        }
        TransitEnvelopeRef::InviteBootstrap {
            sender_endpoint,
            recipient_endpoint,
            bootstrap_hash,
            workspace_id,
            invite_event_id,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err(
                    "invite bootstrap transit addressed to a different endpoint".to_string()
                );
            }
            let invite_secret = invite::schema::invite_secret_by_hash(store, &bootstrap_hash)?;
            if invite_secret.workspace_id != Some(workspace_id)
                || invite_secret.invite_event_id != Some(invite_event_id)
            {
                return Err("invite bootstrap key is not scoped to envelope invite".to_string());
            }
            let associated_data = codec::associated_data_invite_bootstrap(
                &sender_endpoint,
                &recipient_endpoint,
                &bootstrap_hash,
                &workspace_id,
                &invite_event_id,
                &nonce,
            );
            let key = crypto::hkdf_sha256_key(
                &invite_secret.bootstrap_secret,
                INVITE_BOOTSTRAP_PURPOSE,
                &associated_data,
            )?;
            let plaintext =
                crypto::xchacha20poly1305_decrypt(&key, &associated_data, &nonce, ciphertext)?;
            Ok(UnwrappedTransit {
                inners: codec::decode_inner_events(&plaintext)?,
                unwrapped_with: TransitUnwrap::InviteBootstrap {
                    bootstrap_hash,
                    workspace_id,
                    invite_event_id,
                },
                sender_endpoint,
            })
        }
        TransitEnvelopeRef::ConnectionHandshakeResponse {
            request_id,
            sender_endpoint,
            recipient_endpoint,
            responder_ephemeral_public_key,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err(
                    "connection handshake response addressed to a different endpoint".to_string(),
                );
            }
            let associated_data = codec::associated_data_connection_handshake_response(
                &request_id,
                &sender_endpoint,
                &recipient_endpoint,
                &responder_ephemeral_public_key,
                &nonce,
            );
            let Some((request, invite_secret, initiator_ephemeral)) =
                handshake_response_dependencies(store, request_id)?
            else {
                return Ok(UnwrappedTransit {
                    inners: Vec::new(),
                    unwrapped_with: TransitUnwrap::ConnectionHandshake { request_id },
                    sender_endpoint,
                });
            };
            let inner = match connection_response::commands::decrypt_handshake_response(
                connection_response::commands::DecryptHandshakeResponse {
                    request_id,
                    request: &request,
                    invite_secret: &invite_secret,
                    initiator_ephemeral: &initiator_ephemeral,
                    responder_ephemeral_public_key,
                    associated_data: &associated_data,
                    nonce: &nonce,
                    ciphertext,
                },
            ) {
                Ok(inner) => inner,
                Err(err) => return Err(err),
            };
            Ok(UnwrappedTransit {
                inners: vec![inner],
                unwrapped_with: TransitUnwrap::ConnectionHandshake { request_id },
                sender_endpoint,
            })
        }
        TransitEnvelopeRef::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err("connection transit addressed to a different endpoint".to_string());
            }
            let remote = remote_endpoint(&connection_id)?;
            if sender_endpoint != remote {
                return Err("connection transit sender does not match connection".to_string());
            }
            let connection_event = connection_schema::connection_event(store, connection_id)?;
            let connection =
                connection_response::codec::decode(&connection_event).map_err(|_| {
                    "connection transit dependency is not a connection event".to_string()
                })?;
            let associated_data = codec::associated_data_connection(
                &connection_id,
                &sender_endpoint,
                &recipient_endpoint,
                &nonce,
            );
            let key = crypto::hkdf_sha256_key(
                &connection.connection_secret,
                CONNECTION_PURPOSE,
                &associated_data,
            )?;
            let plaintext =
                crypto::xchacha20poly1305_decrypt(&key, &associated_data, &nonce, ciphertext)?;
            Ok(UnwrappedTransit {
                inners: codec::decode_inner_events(&plaintext)?,
                unwrapped_with: TransitUnwrap::Connection { connection_id },
                sender_endpoint,
            })
        }
    }
}

fn handshake_response_dependencies(
    store: &Store,
    request_id: EventId,
) -> Result<
    Option<(
        connection_request::types::RequestEvent,
        invite::types::InviteSecretEvent,
        connection_ephemeral::types::EphemeralSecretEvent,
    )>,
    String,
> {
    let Some(request_bytes) = event_schema::event_bytes(store, &request_id)
        .map_err(|err| format!("load connection request event: {err}"))?
        .or_else(|| connection_schema::connection_event(store, request_id).ok())
    else {
        return Ok(None);
    };
    let request = connection_request::codec::decode(&request_bytes)?;
    let invite_secret_bytes = event_schema::event_bytes(store, &request.invite_secret_event_id)
        .map_err(|err| format!("load invite secret event: {err}"))?
        .ok_or_else(|| "missing invite secret event".to_string())?;
    let invite_secret = invite::codec::decode(&invite_secret_bytes)
        .map_err(|_| "connection dependency is not an invite secret".to_string())?;
    let initiator_bytes =
        event_schema::event_bytes(store, &request.initiator_ephemeral_secret_event_id)
            .map_err(|err| format!("load connection ephemeral event: {err}"))?
            .ok_or_else(|| "missing connection ephemeral event".to_string())?;
    let initiator_ephemeral = connection_ephemeral::codec::decode(&initiator_bytes)
        .map_err(|_| "connection dependency is not an ephemeral secret".to_string())?;
    Ok(Some((request, invite_secret, initiator_ephemeral)))
}

#[cfg(test)]
mod tests {
    use crate::core::network_queues::{InboundNetworkRow, NetworkSource};
    use crate::protocol::event_modules::connection::transit;
    use crate::protocol::event_modules::identity::{endpoint, invite};
    use crate::protocol::Protocol;
    use crate::workers::schema::{self as worker_schema, TransitUnwrap};

    use super::*;

    fn keypair() -> endpoint::types::EndpointKeypair {
        endpoint::commands::create_local_keypair().value
    }

    #[test]
    fn bootstrap_frame_projects_inner_bytes_with_provenance() {
        let local = keypair();
        let remote = keypair();
        let store = Protocol::open_memory_store().expect("open store");
        store
            .insert_table_rows(endpoint::projector::local_endpoint(local))
            .expect("insert local endpoint");
        let inner = b"inner canonical bytes".to_vec();
        let frame = transit::commands::create_bootstrap(&remote, local.endpoint, &inner)
            .expect("create bootstrap frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("addr")),
            frame,
        );

        let output = project_network_in(&store, &inbound, true).expect("project frame");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, worker_schema::CANONICAL_IN);
        store
            .insert_table_rows(output.rows)
            .expect("insert canonical rows");
        let queued = worker_schema::claim_canonical_in(&store, 1).expect("claim canonical");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].canonical_bytes, inner);
        let provenance = queued[0].provenance.expect("provenance");
        assert_eq!(provenance.local_endpoint, local.endpoint);
        assert_eq!(provenance.sender_endpoint, remote.endpoint);
        assert_eq!(provenance.unwrapped_with, TransitUnwrap::Bootstrap);
        assert!(provenance.remember_route);
    }

    #[test]
    fn rejects_frame_for_another_local_endpoint() {
        let local = keypair();
        let other_local = keypair();
        let remote = keypair();
        let store = Protocol::open_memory_store().expect("open store");
        store
            .insert_table_rows(endpoint::projector::local_endpoint(local))
            .expect("insert local endpoint");
        let frame = transit::commands::create_bootstrap(
            &remote,
            other_local.endpoint,
            b"inner canonical bytes",
        )
        .expect("create bootstrap frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("addr")),
            frame,
        );

        let err = project_network_in(&store, &inbound, false).expect_err("wrong endpoint");

        assert!(err.contains("addressed to a different endpoint"), "{err}");
    }

    #[test]
    fn invite_bootstrap_frame_projects_batched_inner_bytes_with_invite_provenance() {
        // Invariant: invite bootstrap decrypts with the invite-secret row and
        // preserves workspace/invite provenance on every recovered event.
        let local = keypair();
        let remote = keypair();
        let bootstrap_secret = [7; 32];
        let bootstrap_hash = invite::types::bootstrap_secret_hash(&bootstrap_secret);
        let workspace_id = [8; 32];
        let invite_event_id = [9; 32];
        let store = Protocol::open_memory_store().expect("open store");
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.extend(invite::projector::invite_secret(
            bootstrap_hash,
            bootstrap_secret,
            Some(workspace_id),
            Some(invite_event_id),
        ));
        store.insert_table_rows(rows).expect("insert local rows");
        let first = b"first identity bytes".to_vec();
        let second = b"second identity bytes".to_vec();
        let frame = transit::commands::create_invite_bootstrap_batch(
            &remote,
            local.endpoint,
            &bootstrap_secret,
            workspace_id,
            invite_event_id,
            vec![first.clone(), second.clone()],
        )
        .expect("create invite bootstrap frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("addr")),
            frame,
        );

        let output = project_network_in(&store, &inbound, false).expect("project frame");

        assert_eq!(output.rows.len(), 2);
        store
            .insert_table_rows(output.rows)
            .expect("insert canonical rows");
        let mut queued = worker_schema::claim_canonical_in(&store, 2).expect("claim canonical");
        queued.sort_by(|left, right| left.canonical_bytes.cmp(&right.canonical_bytes));
        assert_eq!(queued[0].canonical_bytes, first);
        assert_eq!(queued[1].canonical_bytes, second);
        for row in queued {
            let provenance = row.provenance.expect("provenance");
            assert_eq!(provenance.local_endpoint, local.endpoint);
            assert_eq!(provenance.sender_endpoint, remote.endpoint);
            assert_eq!(
                provenance.unwrapped_with,
                TransitUnwrap::InviteBootstrap {
                    bootstrap_hash,
                    workspace_id,
                    invite_event_id,
                }
            );
        }
    }
}
