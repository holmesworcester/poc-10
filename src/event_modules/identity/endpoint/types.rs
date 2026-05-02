pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointKeypair {
    pub endpoint: EndpointId,
    pub secret: [u8; 32],
}
