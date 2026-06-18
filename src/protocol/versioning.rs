//! Protocol versioning scope.
//!
//! Versioning is a protocol scope, not a fact family. It owns the release
//! version constant, the local storage guards that compare projected release
//! marker state with that constant, diagnostic commands such as
//! `state-summary`, and lifecycle intents such as `check_version`.
//!
//! The fact family in this scope is `update`. Update facts are local facts that
//! record a protocol release marker and request rebuild of derived state. Keep
//! fact-family role files (`fact.rs`, `encode.rs`, `author.rs`, `project.rs`,
//! `api.rs`, `cli.rs`) under `versioning/update/`, not in this scope root.
//!
//! Keep two version concepts separate:
//!
//! 1. The release marker is stored protocol state. The recurring
//!    `check_version` intent reads that marker, compares it with the one
//!    `CURRENT_PROTOCOL_VERSION` compiled into this release, and emits a local
//!    update fact when the database needs a rebuild. The update fact is the
//!    repair trigger: its projection requests the generic rebuild effect and
//!    records the new release marker.
//!
//! 2. A projector or query storage requirement is a local safety contract for a
//!    read or write path. A fact family declares the storage version its
//!    projector and query helpers expect, usually next to `PROJECTOR_INFO` in
//!    `project.rs`; query modules import that same constant before reading
//!    materialized rows. This guard is not the release marker and it is not what
//!    triggers rebuild. It is a concurrency and replay safety hatch: normal work
//!    must not consume queue rows or read materialized tables under a storage
//!    shape it did not declare.
//!
//! A given checkout/release carries one protocol version. The protocol code does
//! not contain a live matrix of release versions. Compatibility with older
//! retained facts or older materialized storage belongs in the owning
//! projector/query code that needs it. During an update, that code may read old
//! storage shapes only to derive the current release's state; it must write only
//! the current release's declared tables and effects, never old database tables.
//!
//! Core should remain mechanical here. It may enforce a declared storage
//! requirement at an atomic commit boundary, but protocol modules own the version
//! numbers, the release marker, the recurring check, the update fact, and the
//! per-family compatibility rules.
//!
//! The release rule is deliberately outside core: do not ship code that authors
//! a new durable fact type until every non-deprecated release can decode,
//! authenticate, validate, and project that type. After that release discipline,
//! the local storage marker plus per-route storage guards cover the rest.

pub mod check_version;
pub mod cli;
pub mod queries;
pub mod update;

pub const CURRENT_PROTOCOL_VERSION: u32 = 1;
