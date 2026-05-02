use crux_core::{capability::Operation, Request};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOperation {
    AppendFrame {
        stream_id: String,
        sequence: u64,
        payload: Vec<u8>,
    },
}

impl Operation for StoreOperation {
    type Output = ();
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkOperation {
    SendAck { stream_id: String, sequence: u64 },
}

impl Operation for NetworkOperation {
    type Output = ();
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainOperation {
    DrainReady {
        stream_id: String,
        after_sequence: u64,
    },
}

impl Operation for DrainOperation {
    type Output = ();
}

#[derive(Debug)]
pub enum Effect {
    Store(Request<StoreOperation>),
    Network(Request<NetworkOperation>),
    Drain(Request<DrainOperation>),
}

impl crux_core::Effect for Effect {}

impl From<Request<StoreOperation>> for Effect {
    fn from(request: Request<StoreOperation>) -> Self {
        Self::Store(request)
    }
}

impl From<Request<NetworkOperation>> for Effect {
    fn from(request: Request<NetworkOperation>) -> Self {
        Self::Network(request)
    }
}

impl From<Request<DrainOperation>> for Effect {
    fn from(request: Request<DrainOperation>) -> Self {
        Self::Drain(request)
    }
}
