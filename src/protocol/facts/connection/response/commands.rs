//! User-facing connection response waits.
//!
//! Accept/link commands may need read-your-writes behavior across the local
//! daemon loop: after admitting a request, they wait until the corresponding
//! response fact has projected. The response module owns that polling rule
//! because it knows which projected row answers a request.

use std::time::{Duration, Instant};

use crate::protocol::runtime::ProtocolRuntime;

use super::rows;

pub fn wait_for_request_response(
    runtime: &mut ProtocolRuntime,
    request_id: [u8; 32],
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        runtime.reload_wake_loop_if_store_changed()?;
        if has_response_for_request(runtime, request_id)? {
            return Ok(());
        }
        if has_local_work(runtime) {
            runtime.drain_projection_until_idle(4, 64)?;
            runtime.dispatch_intents(64)?;
            runtime.drain_projection_until_idle(4, 64)?;
            if has_response_for_request(runtime, request_id)? {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("did not produce a connection response".to_string())
}

fn has_local_work(runtime: &ProtocolRuntime) -> bool {
    runtime.wake_loop().pending_len() > 0 || !runtime.wake_loop().intents().is_empty()
}

fn has_response_for_request(
    runtime: &ProtocolRuntime,
    request_id: [u8; 32],
) -> Result<bool, String> {
    let rows = runtime
        .store()
        .table_rows(rows::CONNECTION_RESPONSE_ROWS)
        .map_err(|err| format!("load connection rows: {err}"))?;
    for (key, value) in rows {
        let row = rows::decode_connection_response_row(&key, &value)?;
        if row.request_id == request_id {
            return Ok(true);
        }
    }
    Ok(false)
}
