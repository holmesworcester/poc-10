use std::collections::VecDeque;

use crux_core::{App, Command, Effect};

pub trait EffectHandler<E> {
    fn handle_effect(&mut self, effect: E) -> Result<(), String>;
}

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
