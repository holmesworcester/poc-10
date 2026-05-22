//! Transit frame payload family.
//!
//! Transit frames bundle protocol facts for a connection before the bytes enter
//! `core::network`. This module owns frame layout, frame construction, and
//! receive-side admission helpers. It should stay about protocol frame bytes;
//! socket IO belongs in core and durable meaning belongs in the fact families
//! carried inside the frame.

pub mod create;
pub mod frame;
pub mod layout;
pub mod receive;
pub use crate::core::wire::FixedLayout as TransitFrameDecode;
