//! Content purge projection surface.
//!
//! Purge is the shared semantic context produced by deletion facts. Message and
//! file deletion projectors still own their target-specific authorization, but
//! once authorized they publish the same target coordinate so content projectors
//! and key projectors can react through one role.

pub mod project;
