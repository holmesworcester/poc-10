//! Established connection-frame shared mechanics.
//!
//! Connection frames are encrypted carriers used after a `connection::response`
//! has materialized local connection context. The receive handler classifies
//! raw network bytes into separate ephemeral small, file-slice, or bundle frame
//! facts; their projectors open those bytes with the connection secret and
//! emit durable child facts plus `connection::fact_receipt` records.
//!
//! This helper module owns fixed outer wire layout, sendability checks, and
//! sealing/opening helpers. Core owns socket IO, and the receiving fact
//! families own projection entry points.

pub mod create;
pub mod wire;

pub use crate::core::wire::FixedLayout as ConnectionFrameDecode;
pub use create as receive;
pub use wire as frame;
