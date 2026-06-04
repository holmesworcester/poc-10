use crate::core::facts::Fact;
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::ConnectionResponseSentFact;

pub(crate) struct ConnectionResponseSentAuthenticator;

impl Authenticator for ConnectionResponseSentAuthenticator {
    type Authenticated = ConnectionResponseSentFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_response_sent(fact))
    }
}

fn authenticate_response_sent(fact: &Fact) -> Result<ConnectionResponseSentFact, String> {
    let sent = super::Codec::decode_fact(fact)?;
    verify_fact_id(fact)?;
    if sent.response_id != crate::core::facts::fact_id(&sent.sealed_response_bytes) {
        return Err(
            "connection_response_sent response_id does not match sealed response".to_string(),
        );
    }
    if sent.request_id != sent.response.request_id {
        return Err("connection_response_sent request_id does not match response".to_string());
    }
    if sent.responder_ephemeral_secret_fact_id != sent.response.responder_ephemeral_secret_fact_id {
        return Err("connection_response_sent ephemeral id does not match response".to_string());
    }
    Ok(sent)
}
