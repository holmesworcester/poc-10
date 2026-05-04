//! Minimal Crux command runner.
//!
//! The runner is intentionally only an interpreter for `crux_core::Command`.
//! It does not own a model, choose routes, open files, or decide what an effect
//! means. The caller supplies an app, an initial input, and an effect handler;
//! this module repeatedly feeds generated inputs back into the app until the
//! command graph is drained.
//!
//! This is useful precisely because it is not a framework hidden inside the
//! protocol. If a future command needs authority to touch storage or IO, put
//! that authority in the handler passed to `run`, not in this file. The
//! invariant here is small but important: effects are handled once, generated
//! inputs are replayed in FIFO order, and a command that neither completes nor
//! produces work is reported as a bug instead of spinning.

use std::collections::VecDeque;

use crux_core::{App, Command, Effect};

/// Capability supplied by the caller for one Crux effect type.
///
/// The handler is the only place where effects acquire meaning. Keeping it as a
/// trait rather than a concrete enum lets core stay reusable while tests pass
/// explicit, auditable capabilities to the app they are driving.
pub trait EffectHandler<E> {
    fn handle_effect(&mut self, effect: E) -> Result<(), String>;
}

/// Run one app update and every input it emits until the queue is empty.
///
/// This function is deliberately synchronous and deterministic from the
/// perspective of the supplied handler. It provides no scheduler, retry policy,
/// or hidden background work; callers that need those properties should express
/// them outside core and keep this runner as the mechanical command drain.
pub fn run<A, H>(
    app: &A,
    model: &mut A::Model,
    initial_event: A::Event,
    handler: &mut H,
) -> Result<(), String>
where
    A: App,
    A::Event: Send + 'static,
    H: EffectHandler<A::Effect>,
{
    let mut pending = VecDeque::from([initial_event]);
    while let Some(event) = pending.pop_front() {
        let mut command = app.update(event, model);
        drain_command(&mut command, handler, &mut pending)?;
    }
    Ok(())
}

// Drain one command fully before returning to the input queue. Crux commands can
// emit both effects and follow-up inputs; handling them in batches makes the
// execution order explicit and catches the invalid "stalled" state.
fn drain_command<E, M, H>(
    command: &mut Command<E, M>,
    handler: &mut H,
    pending: &mut VecDeque<M>,
) -> Result<(), String>
where
    E: Effect,
    M: Send + 'static,
    H: EffectHandler<E>,
{
    loop {
        let effects = command.effects().collect::<Vec<_>>();
        let events = command.events().collect::<Vec<_>>();
        let made_progress = !effects.is_empty() || !events.is_empty();

        for effect in effects {
            handler.handle_effect(effect)?;
        }
        pending.extend(events);

        if command.is_done() {
            return Ok(());
        }
        if !made_progress {
            return Err("crux command stalled".to_string());
        }
    }
}
