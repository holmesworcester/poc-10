use crate::core::matchers::ContextMatcher;
use crate::core::pipeline::context_wake::process_context_changes;
use crate::core::pipeline::projection::process_pending_facts;
use crate::core::pipeline::report::{add_pipeline_report, PipelineReport};
use crate::core::projectors::Projector;
use crate::core::store::{Store, TableName};

/// Drive context matching and fact projection until no more work is found.
///
/// The two pipelines intentionally alternate: context changes wake facts;
/// fact projection writes more context changes. The loop stops when neither
/// stage made progress or the projection limit has been reached.
pub(crate) fn process_pending_facts_and_context_changes(
    projector: &(impl Projector + ?Sized),
    matchers: &[&dyn ContextMatcher],
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<PipelineReport, String> {
    let mut total = PipelineReport::default();

    loop {
        let context_report = process_context_changes(store, matchers, limit)?;
        let context_woke_facts = context_report.woken_facts > 0;
        add_pipeline_report(&mut total, context_report);

        if total.projections >= limit {
            break;
        }

        let projection_report = process_pending_facts(
            projector,
            matchers,
            store,
            allowed_tables,
            limit - total.projections,
        )?;
        let projected_facts = projection_report.projections > 0;
        add_pipeline_report(&mut total, projection_report);

        if !context_woke_facts && !projected_facts {
            break;
        }
    }

    Ok(total)
}
