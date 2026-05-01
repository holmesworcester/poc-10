//! Job-shaped runtime modules.
//!
//! After the plan.md update around `OutboxWake` + per-connection
//! `ConnectionSender`, the "sender" is no longer a JobTick-driven sweep but
//! a per-connection actor woken by `OutboxWake(connection_id)` work items.
//! The module still lives under `jobs/` for now so the Phase 10 file
//! layout stays stable while the substrate is migrated; it will move to a
//! dedicated `runtime/sender/` directory in a later refactor.
//!
//! Other jobs (compare scheduler, TTL reaper, blocked-event retry sweep)
//! will continue to land here.

pub mod sender;

pub use sender::{
    schedule_sender_tick, ConnectionSender, DrainResult, SenderTick, SenderTickReport,
};
