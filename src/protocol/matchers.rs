//! Protocol context matcher surface.
//!
//! Fact modules emit these generic need/offer shapes from their projectors.
//! Helper modules are organized by relation, not by fact module.

pub mod coverage;
pub mod exact;
pub mod wrap_source;

pub use coverage::*;
pub use exact::*;
pub use wrap_source::*;
