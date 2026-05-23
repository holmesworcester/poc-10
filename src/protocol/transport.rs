//! Transport scope: network effect-handler modules.
//!
//! Core network code only moves opaque TCP frames through connection-local
//! queues. Transport modules bridge those queues to protocol intents: outbound
//! handlers package already-selected facts into `connection::frame` bytes and
//! stage them for socket writes, while inbound handlers attach receipt metadata
//! and delegate byte classification to the connection family.
//!
//! Keep socket mechanics in `core::network`, encrypted frame meaning in
//! `connection::frame`, and durable receive receipts in
//! `connection::fact_receipt`. Transport modules should not define fact
//! families.

// Intents: bridge protocol facts and core network queues: package facts into
// connection frames, stage outbound bytes, and receive inbound frames.
pub mod receive_network_frame;
pub mod send_facts_on_connection;
pub mod send_network_frame;
