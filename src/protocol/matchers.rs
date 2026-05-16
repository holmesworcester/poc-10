//! Protocol context matcher surface.
//!
//! Fact modules emit these generic need/offer shapes from their projectors.
//! Matcher modules are organized by matching relation, not by fact module.

pub mod coverage;
pub mod exact;
pub mod range;
pub mod wrap_source;

pub use coverage::*;
pub use exact::*;
pub use range::*;
pub use wrap_source::*;
