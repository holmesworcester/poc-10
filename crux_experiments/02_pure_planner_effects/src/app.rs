use crux_core::{App, Command, Core};

use crate::effects::Effect;
use crate::planner::{plan_frame, Frame, PipelinePlan, PlanStep};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    FrameReceived(Frame),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Model {
    pub frames_seen: u64,
    pub last_plan_step_count: usize,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ViewModel {
    pub frames_seen: u64,
    pub last_plan_step_count: usize,
}

#[derive(Debug, Default)]
pub struct PipelineApp;

impl App for PipelineApp {
    type Event = Event;
    type Model = Model;
    type ViewModel = ViewModel;
    type Effect = Effect;

    fn update(
        &self,
        event: Self::Event,
        model: &mut Self::Model,
    ) -> Command<Self::Effect, Self::Event> {
        match event {
            Event::FrameReceived(frame) => {
                let plan = plan_frame(&frame);
                model.frames_seen += 1;
                model.last_plan_step_count = plan.steps().len();
                dispatch_plan(plan)
            }
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        ViewModel {
            frames_seen: model.frames_seen,
            last_plan_step_count: model.last_plan_step_count,
        }
    }
}

pub type PipelineCore = Core<PipelineApp>;

fn dispatch_plan(plan: PipelinePlan) -> Command<Effect, Event> {
    Command::new(|ctx| async move {
        for step in plan.into_steps() {
            match step {
                PlanStep::Store(operation) => ctx.notify_shell(operation),
                PlanStep::Network(operation) => ctx.notify_shell(operation),
                PlanStep::Drain(operation) => ctx.notify_shell(operation),
            }
        }
    })
}
