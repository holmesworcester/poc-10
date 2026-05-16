//! Sync has no owned deferred intent constructors.
//!
//! Sync projectors may decide which facts should travel together, but transit
//! owns the handler payload and idempotence key for sending those facts on a
//! connection.
