//! Baseline: byte-for-byte copy of the current connection_request projector.
//! Lives here so every variant in `attempt_*` has a stable reference point and
//! the shared invariant battery has a known-good baseline to validate.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::ConnectionRequestProjector;
    use crate::projector_experiment::connection_request::shared;

    #[test]
    fn baseline_passes_all_invariants() {
        shared::run_all_invariants(&ConnectionRequestProjector::new());
    }
}
