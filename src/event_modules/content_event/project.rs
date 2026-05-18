//! Poc-10 content-event projector.
//!
//! Validates the fact's declared payload length against its bytes (the layout
//! decoder already checks this) and emits a single `PutRow` for the
//! content_event_rows table.
//!
use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::content_message::{authority, matchers};

use super::layout;
use super::rows::content_event_row;

#[derive(Debug, Clone, Default)]
pub struct ContentEventProjector;

impl ContentEventProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentEventProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded =
            authority::decode_raw_or_signed(fact, layout::TYPE_CONTENT_EVENT, "content event")?;
        let event = layout::decode_fact(&decoded.payload)?;
        let scope = matchers::workspace_scope(event.workspace_id);
        require_fact_scope(fact, &scope)?;
        let signer_need = authority::signer_need(fact.id, decoded.signer);
        if let (Some(signer), Some(need)) = (decoded.signer, signer_need.as_ref()) {
            if !authority::validate_signer_context(
                context,
                need,
                signer,
                event.workspace_id,
                None,
                "content event",
            )? {
                return Ok(output_with_signer_need(signer_need));
            }
        }
        authority::verify_signature(&decoded, "content event")?;

        Ok(output_with_signer_need(signer_need)
            .intent(AtomicIntent::PutRow(content_event_row(fact.id, &event)?).into_intent()))
    }
}

fn output_with_signer_need(
    signer_need: Option<crate::core::context::ContextNeed>,
) -> ProjectionOutput {
    let mut output = ProjectionOutput::new();
    if let Some(need) = signer_need {
        output = output.need(need);
    }
    output
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content event fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope};
    use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::event_modules::content_event::fact::ContentEventFact;
    use topo::event_modules::content_event::{layout, project, rows};
    use topo::event_modules::content_message::matchers as message_context;

    #[test]
    fn content_event_projector_materializes_row_through_atomic_intent() {
        let event = ContentEventFact {
            workspace_id: [9; 32],
            timestamp: 12345,
            payload: vec![0; 17],
        };
        let fact = Fact::new(
            message_context::workspace_scope(event.workspace_id),
            event.timestamp,
            layout::encode_fact(&event).expect("encode content event"),
        );
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &project::ContentEventProjector::new(),
                &[],
                &store,
                &[rows::CONTENT_EVENT_ROWS],
                10,
            )
            .expect("project content event");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 1);
        assert!(bus.intents().is_empty());

        let table = store
            .table_rows(rows::CONTENT_EVENT_ROWS)
            .expect("content event rows");
        assert_eq!(table.len(), 1);
        let row =
            rows::decode_content_event_row(&table[0].0, &table[0].1).expect("decode content row");
        assert_eq!(row.workspace_id, event.workspace_id);
        assert_eq!(row.event_id, fact.id);
        assert_eq!(row.timestamp, 12345);
        assert_eq!(row.payload_bytes, 17);
    }

    #[test]
    fn content_event_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 4]);
        let mut bus = WakeLoop::new();
        bus.submit_fact(fact);
        let err = bus
            .drain(&project::ContentEventProjector::new(), &[], 10)
            .expect_err("malformed bytes must fail projection");
        assert!(err.contains("content event"), "{err}");
    }
}
