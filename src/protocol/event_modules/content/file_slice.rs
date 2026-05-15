//! File slice event leaf.
//!
//! This leaf owns the signed per-slice event used to make file bytes ordinary
//! dependency-ordered content. A slice is useful only with its descriptor:
//! projection relies on `file::rows` for the descriptor row and verifies the
//! BAO proof against that descriptor's root hash. This module does not assemble
//! whole files, choose filenames, or create message/file bundles; those belong
//! to read queries and the content-domain CLI flow.

pub mod commands;
pub mod layout;
pub mod projector;
pub mod queries;
pub mod rows;
pub mod types;
