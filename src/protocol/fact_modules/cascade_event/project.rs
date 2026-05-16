use crate::core::context::ContextNeed;
use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::matchers;

use super::layout;

#[derive(Debug, Clone, Default)]
pub struct CascadeEventProjector;

impl CascadeEventProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for CascadeEventProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let event = layout::decode_fact(&fact.bytes)?;
        if event.timestamp != fact.timestamp {
            return Err("cascade event timestamp does not match fact timestamp".to_string());
        }

        let mut output = ProjectionOutput::new();
        for dependency_id in event.dependencies {
            let need = matchers::exact_event_need(fact.id, fact.scope.clone(), dependency_id);
            if !has_matched_dependency(context, &need, dependency_id) {
                output = output.need(need);
            }
        }

        if output.needs.is_empty() {
            output = output.offer(matchers::exact_event_offer(
                fact.id,
                fact.scope.clone(),
                fact.id,
                fact.id,
            ));
        }
        Ok(output)
    }
}

fn has_matched_dependency(
    context: &ProjectionContext,
    need: &ContextNeed,
    dependency_id: crate::core::facts::FactId,
) -> bool {
    context.offers().iter().any(|offer| {
        offer.role == need.role
            && offer.scope == need.scope
            && offer.selector == need.selector
            && offer.payload_ref == dependency_id
    })
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::matchers::ContextMatcher;
    use crate::core::wake_loop::WakeLoop;

    use super::*;
    use crate::protocol::matchers::exact_event_role;
    use crate::protocol::matchers::ExactSelectorMatcher;

    fn cascade_fact(timestamp: u64, dependencies: Vec<crate::core::facts::FactId>) -> Fact {
        let event = crate::protocol::fact_modules::cascade_event::fact::CascadeEventFact {
            timestamp,
            dependencies,
            payload: [timestamp as u8;
                crate::protocol::fact_modules::cascade_event::fact::PAYLOAD_BYTES],
        };
        Fact::new(
            FactScope::Global,
            timestamp,
            layout::encode_fact(&event).expect("encode cascade event"),
        )
    }

    #[test]
    fn cascade_event_projector_resolves_out_of_order_dependencies() {
        let matcher = ExactSelectorMatcher::new(exact_event_role());
        let dep = cascade_fact(1, Vec::new());
        let child = cascade_fact(2, vec![dep.id]);
        let mut bus = WakeLoop::new();

        bus.submit_fact(child.clone());
        bus.drain(
            &CascadeEventProjector::new(),
            &[&matcher as &dyn ContextMatcher],
            10,
        )
        .expect("child waits");
        assert_eq!(
            bus.context(&child.id).expect("child context").needs.len(),
            1
        );

        bus.submit_fact(dep.clone());
        bus.drain(
            &CascadeEventProjector::new(),
            &[&matcher as &dyn ContextMatcher],
            10,
        )
        .expect("dependency wakes child");

        assert!(bus
            .context(&child.id)
            .expect("child context")
            .needs
            .is_empty());
        assert_eq!(
            bus.context(&child.id).expect("child context").offers.len(),
            1
        );
    }
}
