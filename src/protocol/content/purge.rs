//! Content purge projection surface.
//!
//! Purge is the shared semantic context produced by deletion facts. Message and
//! file deletion projectors still own their target-specific authorization, but
//! once authorized they publish the same target coordinate. Target projectors
//! listen for that coordinate, validate the payload, and self-delete; this
//! module only owns the coordinate shape.

pub mod project;
