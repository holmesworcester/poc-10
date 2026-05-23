//! CLI parsing and rendering for the cascade dependency harness.
//!
//! Cascade facts are synthetic sync fixtures, so their command surface should
//! stay small and explicit: generate a staged dependency graph, then replay it
//! in reverse to exercise context wakeups. This file owns only user-facing
//! argument shape and receipt text; dependency generation and replay mechanics
//! live in `commands`.

pub const GENERATE_DEPS_USAGE: &str = "test-generate-deps COUNT DEPS_PER_FACT";
pub const REPLAY_DEPS_REVERSE_USAGE: &str = "test-replay-deps-reverse";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerateDepsArgs {
    pub count: usize,
    pub deps_per_fact: usize,
}

pub fn parse_generate_deps_args(
    args: crate::core::cli::CliArgs<'_>,
) -> Result<GenerateDepsArgs, String> {
    args.require_len(2, GENERATE_DEPS_USAGE)?;
    Ok(GenerateDepsArgs {
        count: args.parse_positive_usize(0, GENERATE_DEPS_USAGE)?,
        deps_per_fact: args
            .get(1)
            .ok_or_else(|| GENERATE_DEPS_USAGE.to_string())?
            .parse::<usize>()
            .map_err(|_| GENERATE_DEPS_USAGE.to_string())?,
    })
}

pub fn generate_deps_output(
    receipt: &super::commands::GenerateDepsReceipt,
) -> crate::core::cli::CliOutput {
    crate::core::cli::CliOutput::lines(vec![
        format!("staged_facts: {}", receipt.staged_facts),
        format!("deps_per_fact: {}", receipt.deps_per_fact),
        format!("dep_edges: {}", receipt.dep_edges),
    ])
}

pub fn replay_deps_reverse_output(
    receipt: &super::commands::ReplayDepsReceipt,
) -> crate::core::cli::CliOutput {
    crate::core::cli::CliOutput::lines(vec![
        format!("replayed_facts: {}", receipt.replayed_facts),
        format!("applied_facts: {}", receipt.applied_facts),
    ])
}
