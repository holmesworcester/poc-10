//! Baseline: byte-for-byte copy of the current device_invite projector.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::DeviceInviteProjector;
    use crate::projector_experiment::device_invite::shared;

    #[test]
    fn baseline_passes_all_invariants() {
        shared::run_all_invariants(&DeviceInviteProjector::new());
    }
}
