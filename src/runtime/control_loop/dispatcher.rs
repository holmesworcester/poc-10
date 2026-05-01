//! Module registry and `step` dispatch primitive.
//!
//! The control loop calls one function for every claimed work item:
//!
//! ```text
//! step(work_item, context) -> StepResult
//! ```
//!
//! Owners register handlers by `WorkItemKind`. We do *not* implement handlers
//! here — Phase 1 only ships the dispatch primitive. Per `plan.md` line 115:
//! "the control loop has no sync, bootstrap, auth, connection, dependency, or
//! event-type policy."

use std::collections::HashMap;
use std::sync::Arc;

use rusqlite::Connection;

use super::step::StepResult;
use super::work_item::{WorkItem, WorkItemKind};

/// Read-mostly context handed to a handler. The `Connection` is the
/// transactional handle the control loop opened for this `step`; the handler
/// reads its inputs from it and returns `StateUpdates` / `QueueWrites` for
/// the loop to apply.
pub struct StepContext<'a> {
    pub conn: &'a Connection,
    pub now_ms: i64,
    /// Owner identifier (worker name / lease holder), useful for logging.
    pub worker_id: &'a str,
}

/// A handler function for a given `WorkItemKind`. The signature is
/// intentionally narrow: take a typed work item and a context, return a
/// `StepResult`. No global state captured.
pub type StepHandler = Arc<
    dyn Fn(&WorkItem, &StepContext<'_>) -> Result<StepResult, DispatchError> + Send + Sync,
>;

/// Errors the dispatcher itself raises (not handler errors — those go in
/// `Result<StepResult, DispatchError>` per handler).
#[derive(Debug)]
pub enum DispatchError {
    /// No handler is registered for this `WorkItemKind`.
    NoHandler(WorkItemKind),
    /// A handler was registered for this kind, but it was passed a `WorkItem`
    /// whose variant didn't match the kind. Programmer error.
    KindMismatch {
        expected: WorkItemKind,
        actual: WorkItemKind,
    },
    /// Handler returned an error. The string is the handler's message.
    Handler(String),
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchError::NoHandler(k) => {
                write!(f, "no handler registered for WorkItemKind::{:?}", k)
            }
            DispatchError::KindMismatch { expected, actual } => write!(
                f,
                "handler kind mismatch: expected {:?}, got {:?}",
                expected, actual
            ),
            DispatchError::Handler(s) => write!(f, "handler error: {}", s),
        }
    }
}

impl std::error::Error for DispatchError {}

/// Trait implemented by an event/job module to expose handlers to the
/// dispatcher. Modules call `register` once at startup; the registry takes
/// it from there.
///
/// We use a trait so a module can offer multiple handlers atomically (one
/// module may own several `WorkItemKind`s) without exposing its private
/// state to the substrate.
pub trait ModuleHandlers {
    /// Returns the kinds this module handles.
    fn kinds(&self) -> &'static [WorkItemKind];

    /// Returns the handler for `kind`. Must return `Some` for every kind in
    /// `self.kinds()`.
    fn handler(&self, kind: WorkItemKind) -> Option<StepHandler>;
}

/// Registry of `WorkItemKind -> StepHandler`.
#[derive(Default, Clone)]
pub struct ModuleRegistry {
    handlers: HashMap<WorkItemKind, StepHandler>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a single handler. Panics if a handler is already registered
    /// for that kind — the substrate refuses to overwrite, since handler
    /// identity is part of correctness.
    pub fn register(&mut self, kind: WorkItemKind, handler: StepHandler) {
        if self.handlers.contains_key(&kind) {
            panic!(
                "control_loop::ModuleRegistry: kind {:?} is already registered",
                kind
            );
        }
        self.handlers.insert(kind, handler);
    }

    /// Register all handlers from a `ModuleHandlers` impl.
    pub fn register_module<M: ModuleHandlers>(&mut self, module: &M) {
        for kind in module.kinds() {
            let h = module
                .handler(*kind)
                .expect("ModuleHandlers::handler must return Some for kinds() entries");
            self.register(*kind, h);
        }
    }

    pub fn handler_for(&self, kind: WorkItemKind) -> Option<&StepHandler> {
        self.handlers.get(&kind)
    }
}

/// The single dispatch primitive. Look up the handler for the work item's
/// kind, invoke it, and return its `StepResult` (or a dispatch error).
///
/// The control loop is expected to wrap this call in a transaction, then
/// apply `StepResult.state_updates` and `StepResult.queue_writes` inside that
/// transaction, then run `StepResult.effects` outside it. None of that
/// orchestration is done here — this function is the dispatch primitive
/// only.
pub fn step(
    registry: &ModuleRegistry,
    work_item: &WorkItem,
    ctx: &StepContext<'_>,
) -> Result<StepResult, DispatchError> {
    let kind = work_item.kind();
    let handler = registry
        .handler_for(kind)
        .ok_or(DispatchError::NoHandler(kind))?;
    handler(work_item, ctx).map_err(|e| match e {
        DispatchError::Handler(_) | DispatchError::NoHandler(_) | DispatchError::KindMismatch { .. } => {
            e
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::control_loop::work_item::JobTick;

    #[test]
    fn registry_dispatches_by_kind() {
        let mut reg = ModuleRegistry::new();
        let h: StepHandler = Arc::new(|item, _ctx| {
            assert_eq!(item.kind(), WorkItemKind::JobTick);
            Ok(StepResult::empty())
        });
        reg.register(WorkItemKind::JobTick, h);

        let conn = Connection::open_in_memory().unwrap();
        let ctx = StepContext {
            conn: &conn,
            now_ms: 0,
            worker_id: "test",
        };

        let item = WorkItem::JobTick(JobTick {
            job_name: "x".to_string(),
            fired_at_ms: 0,
        });
        let res = step(&reg, &item, &ctx).unwrap();
        assert!(res.state_updates.is_empty());
    }

    #[test]
    fn no_handler_is_an_error() {
        let reg = ModuleRegistry::new();
        let conn = Connection::open_in_memory().unwrap();
        let ctx = StepContext {
            conn: &conn,
            now_ms: 0,
            worker_id: "test",
        };
        let item = WorkItem::JobTick(JobTick {
            job_name: "x".to_string(),
            fired_at_ms: 0,
        });
        let err = step(&reg, &item, &ctx).unwrap_err();
        match err {
            DispatchError::NoHandler(WorkItemKind::JobTick) => {}
            _ => panic!("expected NoHandler"),
        }
    }
}
