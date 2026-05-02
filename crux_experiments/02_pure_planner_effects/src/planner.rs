use crate::effects::{DrainOperation, NetworkOperation, StoreOperation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub stream_id: String,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(stream_id: impl Into<String>, sequence: u64, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            stream_id: stream_id.into(),
            sequence,
            payload: payload.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelinePlan {
    steps: Vec<PlanStep>,
}

impl PipelinePlan {
    pub fn new(steps: Vec<PlanStep>) -> Self {
        Self { steps }
    }

    pub fn steps(&self) -> &[PlanStep] {
        &self.steps
    }

    pub fn into_steps(self) -> Vec<PlanStep> {
        self.steps
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanStep {
    Store(StoreOperation),
    Network(NetworkOperation),
    Drain(DrainOperation),
}

pub fn plan_frame(frame: &Frame) -> PipelinePlan {
    PipelinePlan::new(vec![
        PlanStep::Store(StoreOperation::AppendFrame {
            stream_id: frame.stream_id.clone(),
            sequence: frame.sequence,
            payload: frame.payload.clone(),
        }),
        PlanStep::Network(NetworkOperation::SendAck {
            stream_id: frame.stream_id.clone(),
            sequence: frame.sequence,
        }),
        PlanStep::Drain(DrainOperation::DrainReady {
            stream_id: frame.stream_id.clone(),
            after_sequence: frame.sequence,
        }),
    ])
}
