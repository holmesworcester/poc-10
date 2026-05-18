//! Inline-flat attempt: the entire projector lives in `fn project`, no helpers.
//! The reader's eye never leaves a single function.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::DeviceInviteProjector;
    use crate::projector_experiment::device_invite::shared;

    #[test]
    fn attempt_04_inline_flat_passes_all_invariants() {
        shared::run_all_invariants(&DeviceInviteProjector::new());
    }
}
