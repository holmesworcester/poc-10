#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentEvent {
    pub timestamp: u64,
    pub payload: Vec<u8>,
}
