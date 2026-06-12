//! Connection fact-receipt projector.
//!
//! Receipts publish local observation context for the semantic fact they
//! mention. Projection does not inspect the received payload; it only validates
//! that the receipt is local, decodes cleanly, and can offer
//! `connection_fact_receipt` context keyed by `received_fact_id`.
//!
//! POLICY. A connection_fact_receipt is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and its receipt payload decodes.
//!   2. CONTEXT. No authority context is loaded here; higher-level projectors
//!      validate the receipt against their target fact.
//!   3. MATERIALIZE. Publish a local connection_fact_receipt offer for the
//!      received fact so the owning projector can continue.
//!
//! Change this projector when receipt context shape changes. Request, response,
//! and frame-child projectors own the path-specific proof that consumes the
//! offer.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};

pub fn connection_fact_receipt_for_path(
    input: super::fact::ReceiptPathInput<'_>,
) -> Result<Fact, String> {
    let fact = super::fact::ConnectionFactReceipt {
        received_fact_id: input.received_fact_id,
        origin_addr: super::fact::OriginAddr::new(input.origin_addr)
            .map_err(|err| format!("connection fact receipt origin addr: {err}"))?,
        local_endpoint_id: input.local_endpoint_id,
        sender_endpoint_id: input.sender_endpoint_id,
        receive_path: input.receive_path,
        connection_id: input.connection_id,
        request_id: input.request_id,
        frame_hash: input.frame_hash,
        received_at_local_ms: input.received_at_local_ms,
    };
    Ok(Fact::new(
        FactScope::Local,
        input.received_at_local_ms,
        super::encode::encode_fact(&fact)?,
    ))
}

/// Staged read pipeline for the fact_receipt fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "connection::fact_receipt::Codec",
    authenticate: "connection::fact_receipt::authenticate::ConnectionFactReceiptAuthenticator",
    adapt: "connection::fact_receipt::adapt::ConnectionFactReceiptAdapter",
    project: "connection::fact_receipt::project::ConnectionFactReceiptProjector",
};

#[derive(Debug, Clone, Default)]
pub struct ConnectionFactReceiptProjector;

impl ConnectionFactReceiptProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionFactReceiptProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::ConnectionFactReceiptAuthenticator,
            super::adapt::ConnectionFactReceiptAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<super::fact::ConnectionFactReceipt> for ConnectionFactReceiptProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        received: super::fact::ConnectionFactReceipt,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("connection fact receipt must have FactScope::Local".to_string());
        }
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "connection_fact_receipt",
                crate::core::facts::FactScope::Local,
                received.received_fact_id,
                received.received_fact_id,
            ))
            .row_mutation(RowMutation::PutRow(super::connection_fact_receipt_row(
                fact.id, &received,
            )?)))
    }
}
