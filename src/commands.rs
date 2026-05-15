//! Target command manifest.
//!
//! Commands are pure constructors that turn caller inputs plus a narrow,
//! read-only `CommandContext` into proposed facts and intents. They are not
//! allowed to import worker traits, the event registry, or any protocol-side
//! orchestration shape.

pub mod context;
