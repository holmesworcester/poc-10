//! Transport scope: fact and intent modules.
//!
//! Transport facts are the protocol-visible record of network delivery. Core
//! network code only moves opaque TCP frames through connection-local queues;
//! this area defines encrypted connection frames and the projection that turns
//! opened frames into ordinary protocol facts. Connection fact receipts live
//! under `connection::fact_receipt`, because every accepted inbound payload
//! enters through the connection protocol lifecycle.
//!
//! Keep socket mechanics in `core::network` and keep durable protocol meaning
//! here. Transport intent handlers package facts into frames, send frames
//! through the core network queue, and receive frames by emitting transport
//! facts that projection can validate and fan out.

pub mod connection_frame;

// Intents: bridge protocol facts and core network queues — package facts into
// connection frames, stage outbound bytes, and receive inbound frames.
pub mod receive_network_frame;
pub mod send_facts_on_connection;
pub mod send_network_frame;
