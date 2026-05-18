//! Attempt 01: typed-context accessor with park-on-miss.
//!
//! The projector talks to a `Ctx<'a>` wrapper that hides matcher constructors
//! and returns decoded `Found<T>` payloads whose methods read as English
//! security policy.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::ConnectionRequestProjector;
    use crate::projector_experiment::connection_request::shared;

    #[test]
    fn attempt_01_typed_ctx_passes_all_invariants() {
        shared::run_all_invariants(&ConnectionRequestProjector::new());
    }
}
