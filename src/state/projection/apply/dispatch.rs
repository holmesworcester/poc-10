use super::super::contract::{ContextSnapshot, ProjectorResult};
use crate::event_modules::{registry, ParsedEvent};
use std::cell::RefCell;

// Stage 2 of dropping `recorded_by` (plan.md): the projector signature no
// longer carries a `recorded_by: &str` parameter. The new inbound chain
// uses the workspace_id on each event; the legacy path (CLI/RPC bar)
// still passes a real per-tenant `recorded_by`. To preserve the legacy
// path's tenant-binding semantics until Stage 3 retires the column
// altogether, we stash the caller's `recorded_by` in a thread-local for
// the duration of the projector call. Projectors that want to honour it
// call `current_recorded_by()` and fall back to the chain sentinel.
//
// This bridge is intentionally hidden inside `state/projection/apply` —
// the new inbound chain (`runtime/control_loop`) does NOT touch it, and
// the projector contract remains pure.
thread_local! {
    static CURRENT_RECORDED_BY: RefCell<Option<String>> = RefCell::new(None);
}

/// Run `f` with `recorded_by` available via `current_recorded_by()`.
pub(crate) fn with_recorded_by<R>(recorded_by: &str, f: impl FnOnce() -> R) -> R {
    let prev = CURRENT_RECORDED_BY
        .with(|cell| cell.replace(Some(recorded_by.to_string())));
    let out = f();
    CURRENT_RECORDED_BY.with(|cell| *cell.borrow_mut() = prev);
    out
}

/// Returns the current legacy `recorded_by` if set by the legacy stages
/// caller, or `None` when invoked from the new inbound chain.
pub fn current_recorded_by() -> Option<String> {
    CURRENT_RECORDED_BY.with(|cell| cell.borrow().clone())
}

/// Dispatch to the appropriate pure projector via registry lookup.
///
/// Each event module owns its projector function, registered in EventTypeMeta.
/// No central match statement required — the registry drives dispatch.
pub(crate) fn dispatch_pure_projector(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let type_code = parsed.event_type_code();
    match registry().lookup(type_code) {
        Some(meta) => (meta.projector)(event_id_b64, parsed, ctx),
        None => ProjectorResult::reject(format!("unknown type code {}", type_code)),
    }
}
