//! Unified connection request family.
//!
//! A connection request is first contact for either bootstrap or membership
//! mode. Bootstrap mode is authorized by invite proof; membership mode is
//! authorized by `endpoint_shared` membership. Local commands construct the
//! sealed request fact, received network bytes are admitted as that same fact,
//! and projection validates the selected authority path before offering request
//! context or scheduling response work.
//!
//! This family owns request payload bytes, signing transcripts, and request
//! admission policy. Response creation, frame sending, and socket IO belong to
//! the downstream connection modules.

pub mod authenticate;
pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub use project::{
    connection_for_request_need, connection_for_request_offer, connection_request_need,
    connection_request_offer,
};
