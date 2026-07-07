//! Protocol payload aliases over core wire primitives.
//!
//! This module exists to give protocol payload codecs a stable import surface
//! without making them depend on the broader `wire` module name. It deliberately
//! re-exports only the sequential reader, writer, and error types. Fixed-layout
//! helpers remain in `wire` so low-level encoding rules have one home.

pub use crate::core::wire::{
    Reader as PayloadReader, WireError as PayloadError, Writer as PayloadWriter,
};
