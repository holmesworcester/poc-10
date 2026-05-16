//! Shared command context and output types.
//!
//! User-facing command constructors live with the fact modules that own the
//! facts they create. This module only exposes the narrow context/output
//! contract those constructors share.

pub mod context;
