//! Attempt 03: declarative projector.
//!
//! `project.rs` expresses the policy as a flat list of named checks plus a
//! tiny linear runtime. The structural non-zero field surface is data; the
//! per-dependency steps are short, focused helpers; the top-level `project`
//! reads as a four-step recipe: decode, find invite, validate second
//! dependency by scope, materialize.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::ConnectionRequestProjector;
    use crate::projector_experiment::connection_request::shared;

    #[test]
    fn declarative_passes_all_invariants() {
        shared::run_all_invariants(&ConnectionRequestProjector::new());
    }
}
