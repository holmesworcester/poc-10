//! Connection-request projector readability experiment.
//!
//! `shared` holds scenario builders and the exhaustive invariant battery that
//! every variant must satisfy. `baseline` is the current production projector,
//! used as the control. Each `attempt_*` submodule contributes a fresh
//! rewrite and runs the same battery via its own `#[cfg(test)] mod tests`.

pub mod attempt_01_typed_ctx;
pub mod attempt_02_variant_paths;
pub mod attempt_03_declarative;
pub mod attempt_04_inline_flat;
pub mod attempt_05_freestyle;
pub mod attempt_06_hybrid_polish;
pub mod attempt_07_synthesis;
pub mod baseline;
#[cfg(test)]
pub(crate) mod shared;
