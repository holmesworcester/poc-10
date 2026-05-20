//! Shared byte primitives for compact protocol payload codecs.

pub use crate::core::wire::{
    Reader as PayloadReader, WireError as PayloadError, Writer as PayloadWriter,
};
