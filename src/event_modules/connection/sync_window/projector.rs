//! Projector for `SyncWindowEvent`. No durable state; the control_loop
//! picks up parsed sync_window messages from the work queue and translates
//! them into outgoing have/need intents within the requested window.

use rusqlite::Connection;

use super::event::SyncWindowEvent;

pub fn project(_db: &Connection, _ev: &SyncWindowEvent) -> rusqlite::Result<()> {
    Ok(())
}
