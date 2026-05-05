//! Projector for admin grant events.
//!
//! Projection validates only immediate dependency records supplied by the common
//! worker, then writes one admin row. The current branch can fully validate the
//! workspace-root bootstrap shape and admin-authority workspace continuity. A
//! non-root user dependency needs the identity/user leaf to provide a stable
//! codec before this projector can compare that user's public key.

use crate::protocol::event_modules::types::{event_id, EventId, EventRecord};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::super::workspace;
use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let admin = codec::decode(&event.record.canonical_bytes)?;
    validate_authority(&admin, event)?;
    validate_user_binding(&admin, event)?;
    let admin_id = event_id(&event.record.canonical_bytes);
    Ok(ProjectionOutput::rows(vec![schema::admin_row(
        admin.workspace_id,
        admin_id,
        admin.created_at_ms,
        admin.public_key,
        admin.authority_event_id,
        admin.user_event_id,
    )]))
}

fn validate_authority(
    admin: &super::types::AdminEvent,
    event: &EventWithContext<'_>,
) -> Result<(), String> {
    let workspace_record = require_dependency(event, &admin.workspace_id, "workspace")?;
    workspace::codec::decode(&workspace_record.canonical_bytes)
        .map_err(|_| "admin workspace dependency must be a workspace event".to_string())?;

    if admin.authority_event_id == admin.workspace_id {
        return Ok(());
    }

    let authority_record = require_dependency(event, &admin.authority_event_id, "authority")?;
    let authority_admin = codec::decode(&authority_record.canonical_bytes)
        .map_err(|_| "admin authority must reference a workspace or admin event".to_string())?;
    if authority_admin.workspace_id != admin.workspace_id {
        return Err("admin authority belongs to a different workspace".to_string());
    }
    Ok(())
}

fn validate_user_binding(
    admin: &super::types::AdminEvent,
    event: &EventWithContext<'_>,
) -> Result<(), String> {
    let user_record = require_dependency(event, &admin.user_event_id, "user")?;
    if admin.user_event_id == admin.workspace_id {
        let workspace = workspace::codec::decode(&user_record.canonical_bytes)
            .map_err(|_| "root admin user dependency must be the workspace event".to_string())?;
        if workspace.public_key == admin.public_key {
            return Ok(());
        }
        return Err("admin public_key does not match root workspace public_key".to_string());
    }

    Err("admin user public_key validation awaits identity/user leaf integration".to_string())
}

fn require_dependency<'a>(
    event: &'a EventWithContext<'_>,
    event_id: &EventId,
    name: &'static str,
) -> Result<&'a EventRecord, String> {
    event
        .context
        .dependency(event_id)
        .ok_or_else(|| format!("admin missing {name} dependency"))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::{endpoint, workspace};
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::worker::{DependencyContext, EventContext};

    use super::super::types::AdminEvent;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn make_workspace_record(public_key: [u8; 32]) -> ([u8; 32], Record) {
        let bytes = workspace::codec::encode(&workspace::types::WorkspaceEvent {
            created_at_ms: 10,
            public_key,
            name: "Root".to_string(),
        })
        .expect("encode workspace");
        let id = event_id(&bytes);
        let record = workspace::codec::record_from_bytes(bytes).expect("workspace record");
        (id, record)
    }

    fn admin_record(event: AdminEvent) -> Record {
        codec::record_from_bytes(codec::encode(&event)).expect("admin record")
    }

    fn context_for<'a>(
        record: &'a Record,
        dependencies: Vec<DependencyContext>,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies,
                labels: Vec::new(),
            },
        }
    }

    #[test]
    fn projects_root_admin_from_workspace_authority_and_root_user_binding() {
        let (workspace_id, workspace_record) = make_workspace_record([7; 32]);
        let record = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: [7; 32],
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        });
        let admin_id = event_id(&record.canonical_bytes);
        let output = project(&context_for(
            &record,
            vec![DependencyContext {
                event_id: workspace_id,
                record: workspace_record,
            }],
        ))
        .expect("project admin");

        assert_eq!(output.labels.len(), 0);
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::ADMINS);
        assert_eq!(
            output.rows[0].key,
            schema::admin_key(&workspace_id, &admin_id)
        );
        let row =
            schema::decode_admin_row(&output.rows[0].key, &output.rows[0].value).expect("row");
        assert_eq!(row.workspace_id, workspace_id);
        assert_eq!(row.admin_id, admin_id);
        assert_eq!(row.public_key, [7; 32]);
        assert_eq!(row.authority_event_id, workspace_id);
        assert_eq!(row.user_event_id, workspace_id);
    }

    #[test]
    fn projects_ongoing_admin_when_authority_admin_is_in_same_workspace() {
        let (workspace_id, workspace_record) = make_workspace_record([7; 32]);
        let authority = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: [7; 32],
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        });
        let authority_id = event_id(&authority.canonical_bytes);
        let record = admin_record(AdminEvent {
            created_at_ms: 30,
            workspace_id,
            public_key: [7; 32],
            authority_event_id: authority_id,
            user_event_id: workspace_id,
        });

        let output = project(&context_for(
            &record,
            vec![
                DependencyContext {
                    event_id: workspace_id,
                    record: workspace_record,
                },
                DependencyContext {
                    event_id: authority_id,
                    record: authority,
                },
            ],
        ))
        .expect("project ongoing admin");

        assert_eq!(output.rows.len(), 1);
        let row =
            schema::decode_admin_row(&output.rows[0].key, &output.rows[0].value).expect("row");
        assert_eq!(row.authority_event_id, authority_id);
        assert_eq!(row.workspace_id, workspace_id);
    }

    #[test]
    fn rejects_bootstrap_public_key_that_does_not_match_root_workspace_user() {
        let (workspace_id, workspace_record) = make_workspace_record([7; 32]);
        let record = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: [8; 32],
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        });

        let err = project(&context_for(
            &record,
            vec![DependencyContext {
                event_id: workspace_id,
                record: workspace_record,
            }],
        ))
        .expect_err("mismatched root key must reject");

        assert!(err.contains("admin public_key does not match root workspace public_key"));
    }

    #[test]
    fn rejects_ongoing_admin_authority_from_another_workspace() {
        let (workspace_id, workspace_record) = make_workspace_record([7; 32]);
        let (other_workspace_id, _) = make_workspace_record([9; 32]);
        let authority = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id: other_workspace_id,
            public_key: [9; 32],
            authority_event_id: other_workspace_id,
            user_event_id: other_workspace_id,
        });
        let authority_id = event_id(&authority.canonical_bytes);
        let record = admin_record(AdminEvent {
            created_at_ms: 30,
            workspace_id,
            public_key: [7; 32],
            authority_event_id: authority_id,
            user_event_id: workspace_id,
        });

        let err = project(&context_for(
            &record,
            vec![
                DependencyContext {
                    event_id: workspace_id,
                    record: workspace_record,
                },
                DependencyContext {
                    event_id: authority_id,
                    record: authority,
                },
            ],
        ))
        .expect_err("cross-workspace authority must reject");

        assert_eq!(err, "admin authority belongs to a different workspace");
    }

    #[test]
    fn rejects_non_root_user_until_user_leaf_can_supply_public_key_binding() {
        let (workspace_id, workspace_record) = make_workspace_record([7; 32]);
        let local = endpoint::commands::create_local_keypair().value;
        let user_record = endpoint::codec::record_from_bytes(endpoint::codec::encode(&local))
            .expect("endpoint record");
        let user_id = event_id(&user_record.canonical_bytes);
        let record = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: local.endpoint,
            authority_event_id: workspace_id,
            user_event_id: user_id,
        });

        let err = project(&context_for(
            &record,
            vec![
                DependencyContext {
                    event_id: workspace_id,
                    record: workspace_record,
                },
                DependencyContext {
                    event_id: user_id,
                    record: user_record,
                },
            ],
        ))
        .expect_err("unsupported user dependency must reject");

        assert_eq!(
            err,
            "admin user public_key validation awaits identity/user leaf integration"
        );
    }
}
