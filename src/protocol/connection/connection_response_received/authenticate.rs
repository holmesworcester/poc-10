use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ConnectionResponseReceivedFact;

pub(crate) struct ConnectionResponseReceivedAuthenticator;

impl Authenticator for ConnectionResponseReceivedAuthenticator {
    type Authenticated = ConnectionResponseReceivedFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_response_received(fact))
    }
}

fn authenticate_response_received(fact: &Fact) -> Result<ConnectionResponseReceivedFact, String> {
    let received = super::Codec::decode_fact(fact)?;
    verify_fact_id(fact)?;
    if received.response_id == [0; 32]
        || received.request_id == [0; 32]
        || received.receive_id == [0; 32]
    {
        return Err("connection_response_received ids cannot be empty".to_string());
    }
    Ok(received)
}
