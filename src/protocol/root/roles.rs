//! Shared role ids for generic root refs.
//!
//! Role numbers are protocol vocabulary. Family projectors decide which roles
//! are required and what target type each role may name.

pub const WORKSPACE: u32 = 1;
pub const AUTHOR: u32 = 2;
pub const SIGNER: u32 = 3;
pub const KEY_DOMAIN: u32 = 4;
pub const CONTENT: u32 = 5;
pub const METADATA: u32 = 6;
pub const SECRET: u32 = 7;
pub const TARGET: u32 = 8;
pub const PARENT: u32 = 9;
pub const ATTACHMENT: u32 = 10;
pub const POLICY: u32 = 11;
pub const BLOB: u32 = 12;
pub const FRONTIER: u32 = 13;
pub const SUPERSEDES: u32 = 14;
