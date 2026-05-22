//! Sync fact modules.
//!
//! Sync facts describe what this store has, what a peer needs, and how two
//! stores converge without sending every fact eagerly. Compare facts summarize
//! timestamp ranges, have/need facts request exact ids, shared-fact rows record
//! which facts are shareable on a connection, and cascade facts support test and
//! dependency replay flows.
//!
//! Sync does not decide whether a protocol fact is valid. It transports and
//! advertises facts whose own modules already define layout, scope, and
//! projection policy. When sync receives bytes, those bytes are admitted as
//! ordinary facts and then the normal projection/context/intent machinery
//! decides what they mean.
//!
//! Change these modules for range planning, peer fact advertisement, and
//! connection-scoped sharing behavior. Change the owning fact family when the
//! payload being synced needs a new validation rule.

pub mod cascade_fact;
pub mod compare;
pub mod encrypted_root;
pub mod have_id;
pub mod intent;
pub mod key_wrap_available;
pub mod need_id;
pub mod range_request;
pub mod shared_fact;
