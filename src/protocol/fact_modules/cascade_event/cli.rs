pub const GENERATE_DEPS_USAGE: &str = "generate-deps COUNT DEPS_PER_EVENT";
pub const REPLAY_DEPS_REVERSE_USAGE: &str = "replay-deps-reverse";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerateDepsArgs {
    pub count: usize,
    pub deps_per_event: usize,
}

pub fn parse_generate_deps_args(
    args: crate::core::cli::CliArgs<'_>,
) -> Result<GenerateDepsArgs, String> {
    args.require_len(2, GENERATE_DEPS_USAGE)?;
    Ok(GenerateDepsArgs {
        count: args.parse_positive_usize(0, GENERATE_DEPS_USAGE)?,
        deps_per_event: args
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
        format!("staged_events: {}", receipt.staged_events),
        format!("deps_per_event: {}", receipt.deps_per_event),
        format!("dep_edges: {}", receipt.dep_edges),
    ])
}

pub fn replay_deps_reverse_output(
    receipt: &super::commands::ReplayDepsReceipt,
) -> crate::core::cli::CliOutput {
    crate::core::cli::CliOutput::lines(vec![
        format!("replayed_events: {}", receipt.replayed_events),
        format!("applied_events: {}", receipt.applied_events),
    ])
}
