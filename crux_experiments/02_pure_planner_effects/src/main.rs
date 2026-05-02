use pure_planner_effects::{Effect, Event, Frame, PipelineCore};

fn main() {
    let core = PipelineCore::new();
    let effects = core.process_event(Event::FrameReceived(Frame::new(
        "peer-a",
        7,
        b"hello".to_vec(),
    )));

    for effect in effects {
        match effect {
            Effect::Store(request) => println!("store: {:?}", request.operation),
            Effect::Network(request) => println!("network: {:?}", request.operation),
            Effect::Drain(request) => println!("drain: {:?}", request.operation),
        }
    }
}
