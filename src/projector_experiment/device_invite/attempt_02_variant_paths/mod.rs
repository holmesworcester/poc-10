//! Variant-typed device_invite projector.
//!
//! The bootstrap-vs-delegated split lives in `InviteAuthority`. See
//! `project.rs` for the rationale and shape.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::DeviceInviteProjector;
    use crate::projector_experiment::device_invite::shared;

    #[test]
    fn attempt_02_passes_all_invariants() {
        shared::run_all_invariants(&DeviceInviteProjector::new());
    }
}
