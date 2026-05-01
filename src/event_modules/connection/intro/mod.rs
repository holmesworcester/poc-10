//! `intro` event module.
//!
//! Endpoint-pair introduction: A introduces B and C to each other. Three
//! peers, two subjects, one introducer (`signed_by`). No `workspace_id`.
//!
//! Translated from poc-6 `events/network/intro.py` per `plan.md` lines
//! 204-218. In poc-6 the intro carried only peer ids; in poc-8 we also
//! carry address hints for each subject so the receiving daemon can dial
//! immediately without a separate `observed_address` round-trip.

pub mod event;
pub mod projector;
pub mod registry_meta;
pub mod codec;

pub use event::{IntroAddress, IntroEvent, INTRO_TYPE_CODE};
pub use projector::{ensure_schema, project};
pub use registry_meta::{project_pure, INTRO_META};
pub use codec::{encode, parse, IntroWireError};
