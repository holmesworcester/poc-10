//! Declarative-policy attempt: the projector reads as an ordered checklist of
//! invariants. See `project.rs` for the rationale.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::DeviceInviteProjector;
    use crate::projector_experiment::device_invite::shared;

    #[test]
    fn declarative_passes_all_invariants() {
        shared::run_all_invariants(&DeviceInviteProjector::new());
    }
}
