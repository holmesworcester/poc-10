//! `invite_accepted` event module — local trust-anchor binding written when an
//! invite is accepted.
//!
//! Per-file layout (plan.md per-file rule): `codec.rs` owns encode/parse +
//! registry meta; `projector.rs` owns `ensure_schema`, the pure projector,
//! and the projector-context loader.

pub mod projector;
pub mod codec;

pub use projector::{ensure_schema, project_pure};
pub use codec::{
    encode_invite_accepted, parse_invite_accepted, InviteAcceptedEvent, INVITE_ACCEPTED_FIELDS,
    INVITE_ACCEPTED_META, INVITE_ACCEPTED_WIRE_SIZE,
};
