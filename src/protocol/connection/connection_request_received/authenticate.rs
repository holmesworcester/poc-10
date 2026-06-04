use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ConnectionRequestReceivedFact;

pub(crate) struct ConnectionRequestReceivedAuthenticator;

impl Authenticator for ConnectionRequestReceivedAuthenticator {
    type Authenticated = ConnectionRequestReceivedFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_request_received(fact))
    }
}

fn authenticate_request_received(fact: &Fact) -> Result<ConnectionRequestReceivedFact, String> {
    let received = super::Codec::decode_fact(fact)?;
    verify_fact_id(fact)?;
    if received.request_id == [0; 32] || received.receive_id == [0; 32] {
        return Err("connection_request_received ids cannot be empty".to_string());
    }
    Ok(received)
}
