//! Attempt 08: full checklist.
//!
//! The whole projector body reads as a numbered list of policy-verb helpers.
//! Each helper sits directly below, named to read as English, with a body
//! that fits in ten lines. Need collection is centralized in a single
//! `NeedSet`, so the parking story is "build it as you go, drain it on miss".

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::ConnectionRequestProjector;
    use crate::projector_experiment::connection_request::shared;

    #[test]
    fn full_checklist_passes_all_invariants() {
        shared::run_all_invariants(&ConnectionRequestProjector::new());
    }
}
