//! Intent payload byte primitives.
//!
//! Protocol intent modules own their payload layouts and validation. This small
//! adapter keeps those modules from depending on core's storage/wire namespace
//! directly while still sharing the same length-prefix and integer mechanics.

pub(crate) use crate::core::wire::{
    Reader as PayloadReader, WireError as PayloadError, Writer as PayloadWriter,
};
