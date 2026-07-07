//! Connection protocol scope.
//!
//! A connection is the protocol relationship that starts with an invite-backed
//! request, completes with a local response fact, and then carries encrypted
//! frame bytes for sync and application facts. This scope owns the handshake
//! facts, receive receipts, established-frame facts, and the network-facing
//! intents that turn opaque socket bytes into pipeline input or socket writes.
//!
//! The mechanism is fact-driven. Requests, responses, receipts, and frames all
//! enter projection through typed facts; projectors wait on explicit context
//! needs instead of calling into auth, sync, or core networking directly.
//! Network handlers remain thin boundaries: they normalize metadata, package or
//! stage bytes, and leave semantic validation to the fact family that owns the
//! payload.
//!
//! Change these modules for connection handshake layout, connection-row
//! materialization, receive receipt policy, established-frame admission, or
//! connection network intent behavior. Core owns socket mechanics, sync owns
//! which fact ids should move, and the receiving fact families own the meaning
//! of child facts opened from a frame.

pub mod bootstrap_request;
pub mod bootstrap_response;
pub mod close;
pub mod connection_request;
pub mod connection_response;
pub mod ephemeral_secret;
pub mod fact_receipt;
pub mod frame_bundle;
pub mod frame_file_slice;
pub mod frame_observation;
pub mod frame_small;
pub mod observed_endpoint_address;
pub mod receive_network_frame;

// Intents: delayed handshake work. Projection emits these when a request has
// enough context to answer or when an invite/server bootstrap should send a
// request over the network.
pub mod create_bootstrap_response;
pub mod create_connection_response;
pub mod maintain_connections;
pub mod send_bootstrap_request;
pub mod send_bootstrap_response;
pub mod send_connection_request;
pub mod send_connection_response;
pub mod send_facts_on_connection;
pub mod send_network_frame;
