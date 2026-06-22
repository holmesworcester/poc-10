//! Protocol versioning scope.
//!
//! Versioning is a protocol scope, not a fact family. It owns the release
//! version constant, the recurring check that compares the schema-declared
//! protocol marker with that constant, and the local update fact that runs the
//! version replay rebuild for stale derived state.
//!
//! The fact family in this scope is `local_update`. Local update facts are
//! local facts that record a protocol release marker and request the version
//! replay rebuild: wipe resettable derived/runtime state and replay retained
//! facts. Keep fact-family role files (`fact.rs`, `encode.rs`,
//! `author.rs`, `project.rs`, `api.rs`, `cli.rs`) under
//! `versioning/local_update/`, not in this scope root.
//!
//! Keep two version concepts separate:
//!
//! 1. The recurring version check is protocol responsibility. It reads the
//!    schema-declared protocol marker, compares it with the one
//!    `CURRENT_PROTOCOL_VERSION` compiled into this release, and emits a local
//!    update fact when the database needs a version replay rebuild. The update
//!    fact is the repair trigger: its projection requests the version replay
//!    rebuild effect, records protocol-visible update history, and advances the
//!    schema-declared protocol marker through a normal commit effect.
//!
//! 2. A projector or query storage requirement is a local safety contract for a
//!    read or write path. A fact family declares the storage version its
//!    projector and query helpers expect, usually next to `PROJECTOR_INFO` in
//!    `project.rs`; query modules import that same constant before reading
//!    materialized rows. This guard is not the release marker and it is not what
//!    triggers rebuild. It is a concurrency and replay safety hatch: normal work
//!    must not consume queue rows or read materialized tables under a storage
//!    shape it did not declare.
//!    Core can enforce this automatically for commits, but not for raw reads:
//!    query modules must decide whether to require current storage, deliberately
//!    support an old not-yet-replayed table shape, or act as a maintenance/
//!    diagnostic read that is allowed to inspect stale state.
//!
//! A given checkout/release carries one protocol version. The protocol code does
//! not contain a live matrix of release versions. Compatibility with older
//! retained facts or older materialized storage belongs in the owning
//! projector/query code that needs it. During an update, that code may read old
//! storage shapes only to derive the current release's state; it must write only
//! the current release's declared tables and effects, never old database tables.
//!
//! Core should remain mechanical here. It enforces declared storage requirements
//! at atomic commit boundaries by reading the schema-declared marker, but
//! protocol modules own the marker table, version number, recurring check,
//! update fact, and per-family compatibility rules.
//!
//! The release rule is deliberately outside core: do not ship code that authors
//! a new durable fact type until every non-deprecated release can decode,
//! authenticate, validate, and project that type. After that release discipline,
//! the schema-declared protocol marker plus per-route storage guards cover the rest.

pub mod check_version;
pub mod local_update;

pub const CURRENT_PROTOCOL_VERSION: u32 = 1;
