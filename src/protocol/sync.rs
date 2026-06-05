//! Sync scope: fact and intent modules.
//!
//! Sync facts describe what this store has, what a peer needs, and how two
//! stores converge without sending every fact eagerly. Compare facts summarize
//! timestamp ranges, have/need facts request exact ids, and sync contribution
//! rows record which facts are shareable on a connection.
//!
//! Sync does not decide whether a protocol fact is valid. It sends and
//! advertises facts whose own modules already define layout, scope, and
//! projection policy. When sync receives bytes, those bytes are admitted as
//! ordinary facts and then the normal projection/context/intent machinery
//! decides what they mean.
//!
//! Change these modules for range planning, peer fact advertisement, and
//! connection-scoped sharing behavior. Change the owning fact family when the
//! payload being synced needs a new validation rule.

pub mod compare;
pub mod have_id;
pub mod need_id;
pub mod range_request;
pub mod share_fact_with_sync;
pub mod shared_fact;

// Intents: move peer convergence forward — seed a new connection, respond to
// compares, request missing ids, send requested facts, record sync sharing.
pub mod seed_connection;
pub mod send_compare_response;
pub mod send_needed_fact_id;
pub mod send_requested_fact;
