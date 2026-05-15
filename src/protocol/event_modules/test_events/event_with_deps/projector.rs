//! Projector for dependency-cascade test events.
//!
//! Staged events write their inner shared event bytes into a local replay table.
//! Actual shared dependency events need no projection rows; their purpose is to
//! exercise admission, blocking, and unblocking in the common worker.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{
    ProjectionContext, ProjectionOutput as Poc10ProjectionOutput, Projector,
};
use crate::core::store::TableRow;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::layout;
use super::rows;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    if bytes.first().copied() == Some(layout::TYPE_STAGED_EVENT_WITH_DEPS) {
        let event = layout::decode_staged(bytes)?;
        return Ok(ProjectionOutput::rows(vec![TableRow {
            table: rows::STAGED_EVENTS_WITH_DEPS,
            key: event.index.to_be_bytes().to_vec(),
            value: event.inner_bytes,
        }]));
    }
    layout::decode(bytes)?;
    Ok(ProjectionOutput::default())
}

#[derive(Debug, Clone, Default)]
pub struct Poc10EventWithDepsProjector;

impl Poc10EventWithDepsProjector {
    pub fn new() -> Self {
        Self
    }
}

pub fn event_context_role() -> Role {
    Role::new("event").expect("valid event context role")
}

impl Projector for Poc10EventWithDepsProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<Poc10ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(layout::TYPE_EVENT_WITH_DEPS) => project_poc10_event(fact, context),
            Some(layout::TYPE_STAGED_EVENT_WITH_DEPS) => project_poc10_staged(fact),
            _ => Err("unknown event_with_deps fact type".to_string()),
        }
    }
}

fn project_poc10_event(
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<Poc10ProjectionOutput, String> {
    let record = layout::record_from_bytes(fact.bytes.clone())?;
    let role = event_context_role();
    let mut output = Poc10ProjectionOutput::new();

    for dependency in record.dependencies {
        let selector = Selector::from_bytes(dependency);
        let has_dependency = context.offers().iter().any(|offer| {
            offer.role == role && offer.selector == selector && offer.payload_ref == dependency
        });
        if !has_dependency {
            output = output.need(ContextNeed {
                owner: fact.id,
                role: role.clone(),
                scope: fact.scope.clone(),
                selector,
            });
        }
    }

    if !output.needs.is_empty() {
        return Ok(output);
    }

    Ok(output.offer(ContextOffer {
        owner: fact.id,
        role,
        scope: fact.scope.clone(),
        selector: Selector::from_bytes(fact.id),
        payload_ref: fact.id,
    }))
}

fn project_poc10_staged(fact: &Fact) -> Result<Poc10ProjectionOutput, String> {
    let staged = layout::decode_staged(&fact.bytes)?;
    Ok(Poc10ProjectionOutput::new().intent(
        AtomicIntent::PutRow(TableRow {
            table: rows::STAGED_EVENTS_WITH_DEPS,
            key: staged.index.to_be_bytes().to_vec(),
            value: staged.inner_bytes,
        })
        .into_intent(),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::types::{EventWithDeps, StagedEventWithDeps, PAYLOAD_BYTES};
    use super::*;

    fn inner_bytes_fixture() -> Vec<u8> {
        layout::encode(&EventWithDeps {
            timestamp: 42,
            dependencies: vec![[1; 32], [2; 32]],
            payload: [7; PAYLOAD_BYTES],
        })
    }

    #[test]
    fn shared_event_projects_no_rows() {
        let output = project(&inner_bytes_fixture()).expect("project shared");

        assert!(output.legacy_rows().is_empty());
        assert!(output.legacy_labels().is_empty());
    }

    #[test]
    fn staged_event_projects_inner_bytes_by_index() {
        let inner_bytes = inner_bytes_fixture();
        let staged = layout::encode_staged(&StagedEventWithDeps {
            index: 17,
            inner_bytes: inner_bytes.clone(),
        });

        let output = project(&staged).expect("project staged");

        assert_eq!(output.legacy_rows().len(), 1);
        assert_eq!(output.legacy_rows()[0].table, rows::STAGED_EVENTS_WITH_DEPS);
        assert_eq!(output.legacy_rows()[0].key, 17u64.to_be_bytes());
        assert_eq!(output.legacy_rows()[0].value, inner_bytes);
    }

    #[test]
    fn rejects_malformed_bytes() {
        let err = project(&[layout::TYPE_EVENT_WITH_DEPS]).expect_err("reject");

        assert!(err.contains("length mismatch"));
    }

    #[test]
    fn poc10_shared_event_waits_for_dependency_context() {
        let dep = layout::encode(&EventWithDeps {
            timestamp: 1,
            dependencies: Vec::new(),
            payload: [1; PAYLOAD_BYTES],
        });
        let dep_fact = Fact::new(crate::core::facts::FactScope::Global, 1, dep);
        let child = layout::encode(&EventWithDeps {
            timestamp: 2,
            dependencies: vec![dep_fact.id],
            payload: [2; PAYLOAD_BYTES],
        });
        let child_fact = Fact::new(crate::core::facts::FactScope::Global, 2, child);

        let output = Poc10EventWithDepsProjector::new()
            .project(&child_fact, &ProjectionContext::new(Vec::new()))
            .expect("project child");

        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.needs[0].owner, child_fact.id);
        assert_eq!(output.needs[0].selector.as_bytes(), dep_fact.id);
        assert!(output.offers.is_empty());
        assert!(output.intents.is_empty());
    }

    #[test]
    fn poc10_staged_event_emits_atomic_row_intent() {
        let inner_bytes = inner_bytes_fixture();
        let staged = layout::encode_staged(&StagedEventWithDeps {
            index: 17,
            inner_bytes: inner_bytes.clone(),
        });
        let fact = Fact::new(crate::core::facts::FactScope::Local, 0, staged);

        let output = Poc10EventWithDepsProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect("project staged");

        assert!(output.needs.is_empty());
        assert!(output.offers.is_empty());
        assert_eq!(output.intents.len(), 1);
    }
}
