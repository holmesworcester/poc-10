use crux_core::Core;
use module_deciders_crux_poc::module::{CanonicalEvent, Command};
use module_deciders_crux_poc::{AdmissionOutcome, ApplyReceipt, Effect, LedgerApp, Message};

fn main() {
    let core = Core::<LedgerApp>::default();

    let mut admission = match core
        .process_event(Message::Submit(Command::Deposit { cents: 1250 }))
        .pop()
        .expect("admission request")
    {
        Effect::Admission(request) => request,
        Effect::Apply(_) => panic!("first request should be admission"),
    };

    let admitted = vec![CanonicalEvent::Deposited { cents: 1250 }];
    let mut apply = match core
        .resolve(
            &mut admission,
            AdmissionOutcome::Accepted {
                events: admitted.clone(),
            },
        )
        .expect("admission resolution")
        .pop()
        .expect("apply request")
    {
        Effect::Admission(_) => panic!("second request should be apply"),
        Effect::Apply(request) => request,
    };

    core.resolve(&mut apply, ApplyReceipt { applied_events: 1 })
        .expect("apply resolution");

    println!("{:?}", core.view());
}
