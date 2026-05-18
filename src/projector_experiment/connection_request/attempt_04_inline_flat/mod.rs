//! Inline-flat variant. All projector logic lives inside one `fn project()`
//! so a newcomer reads top-to-bottom without scope-hopping.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::ConnectionRequestProjector;
    use crate::projector_experiment::connection_request::shared;

    #[test]
    fn inline_flat_passes_all_invariants() {
        shared::run_all_invariants(&ConnectionRequestProjector::new());
    }
}
