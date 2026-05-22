//! Concrete protocol fact modules grouped by protocol theme.
//!
//! This is the navigational map for protocol state. Core stores immutable fact
//! bytes, but these modules decide what those bytes mean: identity, encryption,
//! content, connection setup, sync, and transport receipt state. The grouping is
//! thematic so a reader can follow a protocol concern from command creation,
//! through fact layout and projection, into derived rows and queries.
//!
//! Each leaf module owns one fact family or a tightly related set of facts. The
//! usual shape is `fact.rs` for typed payloads, `layout.rs` for stable bytes,
//! `project.rs` for admission and derived state, `rows.rs` for projected SQL
//! rows, `queries.rs` for user-facing reads, and `commands.rs` or `create.rs`
//! for constructors. Not every fact needs every file, but new fact work should
//! keep those responsibilities local instead of spreading protocol meaning into
//! core or the registry.
//!
//! To understand a fact, start in its module root, then read `layout.rs` and
//! `project.rs`. To change how it appears to users, look for `queries.rs` or
//! command helpers. To change how it participates in runtime dependencies,
//! update its projector and the context roles registered in
//! `protocol::registry`.

pub mod connection;
pub mod content;
pub mod encryption;
pub mod identity;
pub mod sync;
pub mod transport;
