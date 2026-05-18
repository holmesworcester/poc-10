//! Attempt 06: hybrid polish.
//!
//! Borrows the inline-flat single-function shape from `attempt_04_inline_flat`
//! and folds in the `REQUIRED_FIELDS` table plus `require(cond, msg)?`
//! micro-helper from `attempt_03_declarative`. The signing transcript stays
//! built at the verification site, on purpose: the reader never has to chase
//! a helper to learn what is being signed.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::ConnectionRequestProjector;
    use crate::projector_experiment::connection_request::shared;

    #[test]
    fn hybrid_polish_passes_all_invariants() {
        shared::run_all_invariants(&ConnectionRequestProjector::new());
    }
}
