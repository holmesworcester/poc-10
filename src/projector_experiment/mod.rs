//! Projector readability experiment.
//!
//! Each subdirectory owns:
//!   * `shared.rs`   - exhaustive invariant battery generic over `Projector`
//!   * `baseline/`   - byte-for-byte copy of the current production projector
//!   * `attempt_*/`  - rewrites that must pass the shared battery
//!
//! Variants live behind `#[cfg(test)]` so they cost nothing in release builds.

#[cfg(test)]
pub mod checks;
pub mod connection_request;
pub mod device_invite;
