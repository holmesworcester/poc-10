//! Connection-request projector readability experiment.
//!
//! `shared` holds scenario builders and the exhaustive invariant battery that
//! every variant must satisfy. `baseline` is the current production projector,
//! used as the control. Each `attempt_*` submodule contributes a fresh
//! rewrite and runs the same battery.

pub mod baseline;
#[cfg(test)]
pub(crate) mod shared;
