//! Transport intent modules.
//!
//! Transport intents bridge protocol facts and core network queues. One side
//! packages facts into connection transit frames and stages outbound bytes; the
//! other receives local inbound frames and emits transit-received facts. Keep
//! TCP mechanics in `core::network` and keep fact admission/projection policy
//! in transport facts.

pub mod receive_transit_frame;
pub mod send_facts_on_connection;
pub mod send_network_frame;
