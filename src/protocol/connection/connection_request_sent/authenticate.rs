use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ConnectionRequestSentFact;

pub(crate) struct ConnectionRequestSentAuthenticator;

impl Authenticator for ConnectionRequestSentAuthenticator {
    type Authenticated = ConnectionRequestSentFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_request_sent(fact))
    }
}

fn authenticate_request_sent(fact: &Fact) -> Result<ConnectionRequestSentFact, String> {
    let sent = super::Codec::decode_fact(fact)?;
    verify_fact_id(fact)?;
    if sent.request_id == [0; 32] {
        return Err("connection_request_sent request_id cannot be empty".to_string());
    }
    if sent.request_id != crate::core::facts::fact_id(&sent.sealed_request_bytes) {
        return Err("connection_request_sent request_id does not match sealed request".to_string());
    }
    if sent.initiator_ephemeral_secret_fact_id != sent.request.initiator_ephemeral_secret_fact_id {
        return Err("connection_request_sent ephemeral id does not match request".to_string());
    }
    Ok(sent)
}
