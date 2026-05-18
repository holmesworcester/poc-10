//! Variant-typed rewrite of the connection_request projector.
//!
//! Lifts the `fact.scope == Local` in-band signal into a `RequestOrigin` enum
//! so the bootstrap-vs-received policy split is a `match`, not a field check.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::ConnectionRequestProjector;
    use crate::projector_experiment::connection_request::shared;

    #[test]
    fn variant_paths_passes_all_invariants() {
        shared::run_all_invariants(&ConnectionRequestProjector::new());
    }
}
