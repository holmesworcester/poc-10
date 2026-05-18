//! Wave-2 synthesis variant. Splits the projector into `plan` (policy) and
//! `project` (output shaping) around a small `Plan` enum that names the
//! three-way outcome of every projector.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::ConnectionRequestProjector;
    use crate::projector_experiment::connection_request::shared;

    #[test]
    fn synthesis_passes_all_invariants() {
        shared::run_all_invariants(&ConnectionRequestProjector::new());
    }
}
