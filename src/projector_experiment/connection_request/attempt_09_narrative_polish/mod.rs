//! Attempt 09: narrative polish.
//!
//! The wave-1 freestyle (attempt_05) had the right shape — a numbered English
//! security policy at the top, code below that mirrors it 1:1 — but it routed
//! park through `Err` via a custom `Verdict` enum, inverting `?` semantics.
//! This attempt keeps the narrative idiom but uses Rust's normal channels:
//! `?` carries rejections, `Ok(NeedSet::park())` carries parking. The shared
//! `checks::{require, is_zero32, NeedSet}` helpers do the structural work.
//!
//! Reading order: read the top-of-file doc-comment in `project.rs` (the
//! spec), then read the function body (the implementation). Each numbered
//! `// 1.`, `// 2.`, ... section in the body matches a numbered rule in the
//! doc. Rule text lives in only one place.

pub mod project;

#[cfg(test)]
mod tests {
    use super::project::ConnectionRequestProjector;
    use crate::projector_experiment::connection_request::shared;

    #[test]
    fn narrative_polish_passes_all_invariants() {
        shared::run_all_invariants(&ConnectionRequestProjector::new());
    }
}
