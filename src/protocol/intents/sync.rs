//! Sync intent modules.
//!
//! Sync intents move peer convergence forward after projection or transport
//! creates queued work: seed a new connection, respond to compares, request
//! missing ids, send requested facts, and mark facts shareable. They operate on
//! sync rows and exact facts; they do not validate the semantic payloads of the
//! facts being synchronized.

pub mod seed_connection;
pub mod send_compare_response;
pub mod send_needed_fact_id;
pub mod send_requested_fact;
pub mod share_fact_with_workspace;
