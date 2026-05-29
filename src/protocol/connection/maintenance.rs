//! Connection-maintenance-owned state.
//!
//! Connection maintenance owns a candidate index: the set of peers the local
//! endpoint should keep trying to bootstrap a connection to. This is not a fact
//! family; it is derived operational state rebuilt from retained request facts
//! during replay and read by the live `maintain_connections` loop. This scope
//! module owns the candidate row codec, the candidate read helpers, and the
//! status view; the `register_connection_candidate`,
//! `unregister_connection_candidate`, and `maintain_connections` intent handlers
//! mutate and read the index only through these helpers.

pub mod index;
