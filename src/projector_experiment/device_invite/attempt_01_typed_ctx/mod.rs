//! Attempt 01: typed-context accessor + park-on-miss.
//!
//! See `project.rs` for the idiom in detail.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::DeviceInviteProjector;
    use crate::projector_experiment::device_invite::shared;

    #[test]
    fn typed_ctx_passes_all_invariants() {
        shared::run_all_invariants(&DeviceInviteProjector::new());
    }
}
