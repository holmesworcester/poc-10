use crux_core::Core;
use module_deciders_crux_poc::module::{
    decide, project_all, CanonicalEvent, Command as ModuleCommand, Projection, Rejection,
};
use module_deciders_crux_poc::{AdmissionOutcome, ApplyReceipt, Effect, LedgerApp, Message};

#[test]
fn module_decider_and_projector_are_deterministic_and_do_not_mutate_inputs() {
    let projection = Projection {
        balance_cents: 1_000,
        applied_events: 4,
    };
    let original_projection = projection.clone();
    let command = ModuleCommand::Withdraw { cents: 375 };

    let first_decision = decide(&projection, &command);
    let second_decision = decide(&projection, &command);

    assert_eq!(first_decision, second_decision);
    assert_eq!(projection, original_projection);

    let events = first_decision.expect("withdraw should be allowed");
    assert_eq!(events, vec![CanonicalEvent::Withdrawn { cents: 375 }]);

    let first_projection = project_all(&projection, &events);
    let second_projection = project_all(&projection, &events);

    assert_eq!(first_projection, second_projection);
    assert_eq!(projection, original_projection);
    assert_eq!(
        first_projection,
        Projection {
            balance_cents: 625,
            applied_events: 5,
        }
    );
}

#[test]
fn crux_requests_admission_then_apply_for_accepted_canonical_events() {
    let core = Core::<LedgerApp>::default();

    let effects = core.process_event(Message::Submit(ModuleCommand::Deposit { cents: 250 }));
    assert_eq!(effects.len(), 1);
    assert_eq!(core.view().balance_cents, 0);

    let mut admission = match effects.into_iter().next().expect("admission request") {
        Effect::Admission(request) => request,
        Effect::Apply(_) => panic!("deposit should request admission first"),
    };

    assert_eq!(
        admission.operation.candidate_events,
        vec![CanonicalEvent::Deposited { cents: 250 }]
    );

    let admitted_events = admission.operation.candidate_events.clone();
    let effects = core
        .resolve(
            &mut admission,
            AdmissionOutcome::Accepted {
                events: admitted_events.clone(),
            },
        )
        .expect("admission request should resolve");

    assert_eq!(effects.len(), 1);
    assert_eq!(core.view().balance_cents, 250);

    let mut apply = match effects.into_iter().next().expect("apply request") {
        Effect::Admission(_) => panic!("accepted admission should request apply"),
        Effect::Apply(request) => request,
    };
    assert_eq!(apply.operation.events, admitted_events);

    let effects = core
        .resolve(&mut apply, ApplyReceipt { applied_events: 1 })
        .expect("apply request should resolve");

    assert!(effects.is_empty());
    assert_eq!(
        core.view().last_apply_receipt,
        Some(ApplyReceipt { applied_events: 1 })
    );
}

#[test]
fn crux_does_not_request_shell_effects_when_module_rejects_command() {
    let core = Core::<LedgerApp>::default();

    let effects = core.process_event(Message::Submit(ModuleCommand::Withdraw { cents: 1 }));

    assert!(effects.is_empty());
    assert_eq!(
        core.view().last_rejection,
        Some(Rejection::InsufficientFunds {
            requested_cents: 1,
            available_cents: 0,
        })
    );
}

#[test]
fn admission_rejection_stops_before_projection_or_apply_request() {
    let core = Core::<LedgerApp>::default();

    let mut admission = match core
        .process_event(Message::Submit(ModuleCommand::Deposit { cents: 500 }))
        .pop()
        .expect("admission request")
    {
        Effect::Admission(request) => request,
        Effect::Apply(_) => panic!("deposit should request admission first"),
    };

    let effects = core
        .resolve(
            &mut admission,
            AdmissionOutcome::Rejected {
                reason: "duplicate command id".to_string(),
            },
        )
        .expect("admission rejection should resolve");

    let view = core.view();
    assert!(effects.is_empty());
    assert_eq!(view.balance_cents, 0);
    assert_eq!(
        view.last_admission_rejection,
        Some("duplicate command id".to_string())
    );
}
