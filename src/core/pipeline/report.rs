#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineReport {
    pub projections: usize,
    pub woken_facts: usize,
    pub intents: usize,
}

/// Merge one stage report into the runtime-visible total.
pub(super) fn add_pipeline_report(total: &mut PipelineReport, report: PipelineReport) {
    total.projections += report.projections;
    total.woken_facts += report.woken_facts;
    total.intents += report.intents;
}
