//! Transport scope: fact and intent modules.
//!
//! Transport facts are the protocol-visible record of network delivery. Core
//! network code only moves opaque TCP frames through connection-local queues;
//! this area defines transit payloads, received-frame facts, origin address
//! normalization, and the projection that turns inbound frames into ordinary
//! protocol facts.
//!
//! Keep socket mechanics in `core::network` and keep durable protocol meaning
//! here. Transport intent handlers package facts into frames, send frames
//! through the core network queue, and receive frames by emitting transport
//! facts that projection can validate and fan out.

pub mod transit;
pub mod transit_received;

// Intents: bridge protocol facts and core network queues — package facts into
// transit frames, stage outbound bytes, and receive inbound frames.
pub mod receive_transit_frame;
pub mod send_facts_on_connection;
pub mod send_network_frame;
