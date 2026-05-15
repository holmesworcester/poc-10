//! Driver for inbound transit frame admission.
//!
//! Decodes the outer transit envelope through the `event_modules::transit`
//! layout helpers, picks the small or large size class, and would emit the
//! recovered inner fact for admission. Inner AEAD opening depends on the
//! connection-secret fact context, which is not yet wired into this handler;
//! the driver therefore stops with a clear retryable error after the public
//! envelope has been authenticated, leaving the intent queued so a later turn
//! can complete the work when secret context is available.

use crate::core::handler_dispatch::{HandlerContext, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;
use crate::event_modules::transit::layout::{
    peek_frame_header, TransitSmallV1, TRANSIT_FRAME_SIZE_CLASS_LARGE,
    TRANSIT_FRAME_SIZE_CLASS_SMALL, TRANSIT_LARGE_WIRE_BYTES, TRANSIT_SMALL_WIRE_BYTES,
};
use crate::event_modules::transit::TransitFrameDecode;

use super::intent::{decode_receive_transit_frame, RECEIVE_TRANSIT_FRAME};

/// Connection secret fact context is required to open the inner AEAD payload.
/// Until that context is wired through the handler dispatcher this driver
/// completes only the public envelope decode and returns this error so the
/// intent stays queued for retry instead of dropping the frame.
pub const INNER_OPEN_NOT_WIRED: &str = "connection secret context not yet wired";

#[derive(Debug, Clone, Default)]
pub struct ReceiveTransitHandler;

impl ReceiveTransitHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for ReceiveTransitHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == RECEIVE_TRANSIT_FRAME
    }

    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_receive_transit_frame(intent)?;
        let bytes = input.frame.as_slice();

        let header = peek_frame_header(bytes)
            .map_err(|err| format!("receive transit: malformed frame header: {err:?}"))?;

        match header.size_class {
            TRANSIT_FRAME_SIZE_CLASS_SMALL => {
                if bytes.len() != TRANSIT_SMALL_WIRE_BYTES {
                    return Err(format!(
                        "receive transit: small frame wrong outer length: expected {} got {}",
                        TRANSIT_SMALL_WIRE_BYTES,
                        bytes.len()
                    ));
                }
                let _frame =
                    <TransitSmallV1 as TransitFrameDecode>::decode(bytes).map_err(|err| {
                        format!("receive transit: small frame decode failed: {err:?}")
                    })?;
                Err(INNER_OPEN_NOT_WIRED.to_string())
            }
            TRANSIT_FRAME_SIZE_CLASS_LARGE => {
                if bytes.len() != TRANSIT_LARGE_WIRE_BYTES {
                    return Err(format!(
                        "receive transit: large frame wrong outer length: expected {} got {}",
                        TRANSIT_LARGE_WIRE_BYTES,
                        bytes.len()
                    ));
                }
                // Large frames are ~1 MiB. The public header is already
                // validated by `peek_frame_header` and the outer length is
                // checked above. The inner payload slot is not materialized
                // here because the inner-open step is not wired yet and
                // dropping a 1 MiB structure onto the dispatch stack is
                // wasteful. The future inner-open path should stream the
                // payload slot directly into AEAD opening.
                Err(INNER_OPEN_NOT_WIRED.to_string())
            }
            other => Err(format!("receive transit: unknown frame size class {other}")),
        }
    }
}
