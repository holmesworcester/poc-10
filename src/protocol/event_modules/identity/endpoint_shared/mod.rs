pub mod codec;
pub mod commands;
pub mod projector;
pub mod schema;
pub mod types;

#[cfg(test)]
mod tests {
    use crate::core::store::Store;
    use crate::protocol::event_modules::worker::{self, AdmitRecords, DrainUntilIdle};
    use crate::protocol::event_modules::Modules;

    use super::super::{device_invite, workspace};
    use super::*;

    #[derive(Default)]
    struct NoMembership;

    impl commands::EndpointMembershipRead for NoMembership {
        fn endpoint_membership(
            &self,
            _endpoint_id: super::super::endpoint::types::EndpointId,
            _workspace_id: crate::protocol::event_modules::types::EventId,
        ) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
    }

    #[test]
    fn admits_received_device_invite_then_signed_endpoint_shared_join() {
        let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
            created_at_ms: 1,
            public_key: [1; 32],
            name: "Workspace".to_string(),
        })
        .expect("create workspace");
        let workspace_id = workspace.value.workspace_id;
        let authority = workspace::commands::create(workspace::commands::CreateWorkspace {
            created_at_ms: 2,
            public_key: [2; 32],
            name: "Authority".to_string(),
        })
        .expect("create authority");
        let user_authority_event_id = authority.value.workspace_id;
        let invite = device_invite::commands::create_with_private_key(
            device_invite::commands::CreateDeviceInvite {
                created_at_ms: 3,
                workspace_id,
                user_authority_event_id,
            },
            [7; 32],
        )
        .expect("create device invite");
        let device_invite_id = invite.value.device_invite_id;
        let private_key = invite.value.keypair.private_key;
        let shared = commands::share_endpoint(
            &NoMembership,
            commands::ShareEndpoint {
                created_at_ms: 4,
                workspace_id,
                user_authority_event_id,
                endpoint_id: [3; 32],
                device_name: "laptop".to_string(),
                device_invite_id,
                device_invite_private_key: private_key,
            },
        )
        .expect("share endpoint");
        let endpoint_shared_id = shared.value.endpoint_shared_id;

        let received_records = workspace
            .events
            .into_iter()
            .chain(authority.events)
            .chain(invite.events)
            .chain(shared.events)
            .map(|event| event.into_record())
            .collect();
        let store = Store::open_memory_with_schemas(&crate::protocol::event_modules::schemas())
            .expect("open store");
        let modules = Modules::new();

        let report = worker::run(
            &store,
            &modules,
            AdmitRecords {
                records: received_records,
            },
        )
        .expect("admit received records");
        assert_eq!(report.blocked_events, 0);
        worker::run(
            &store,
            &modules,
            DrainUntilIdle {
                batch_size: worker::DEFAULT_READY_BATCH,
            },
        )
        .expect("drain ready");

        let membership_key = schema::endpoint_membership_key([3; 32], workspace_id);
        let membership_value = store
            .table_row(schema::ENDPOINT_MEMBERSHIPS, &membership_key)
            .expect("load membership")
            .expect("membership row");
        let membership = schema::decode_endpoint_membership_row(&membership_key, &membership_value)
            .expect("decode membership");
        assert_eq!(membership.endpoint_id, [3; 32]);
        assert_eq!(membership.workspace_id, workspace_id);
        assert_eq!(membership.endpoint_shared_id, endpoint_shared_id);
        assert_eq!(membership.user_authority_event_id, user_authority_event_id);
        assert_eq!(membership.device_invite_id, device_invite_id);

        let duplicate = commands::share_endpoint(
            &store,
            commands::ShareEndpoint {
                created_at_ms: 5,
                workspace_id,
                user_authority_event_id,
                endpoint_id: [3; 32],
                device_name: "second".to_string(),
                device_invite_id,
                device_invite_private_key: private_key,
            },
        )
        .expect_err("duplicate endpoint/workspace must fail");
        assert_eq!(duplicate, "endpoint is already joined to workspace");
    }
}
