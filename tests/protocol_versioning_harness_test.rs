//! Synthetic release-fixture tests for protocol versioning.
//!
//! These tests avoid real protocol fact families so they can run while the
//! family role-file cutover is in progress. The fixture models the important
//! behavior: a read-ahead release can project old and new fact bytes through
//! protocol-local version adapters, while write activation remains fixed by the
//! release profile.

use topo::core::db::TableName;
use topo::core::effects::StorageRequirement;
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{RowMutation, Value};
use topo::core::project_fact::{verify_fact_id, FactRoute};
use topo::core::project_fact::{ProjectionContext, ProjectionOutput};
use topo::core::versioning::{
    active_from_protocol_for_tag, bundle_for_protocol, classify_received_fact, compute_ceiling,
    validate_fact_version_manifest, FactVersionManifestEntry, FactVersionProjector,
    FactVersionRoute, FamilyVersion, FamilyWriter, IngressClassification, PendingReason,
    ProtocolBundle, ProtocolRange, ReleaseManifestEntry, ReleaseProfile, TrustedTime,
    WriteVersionError,
};

const FAMILY: &str = "version_fixture";
const OTHER_FAMILY: &str = "unchanged_fixture";
const TYPE_FIXTURE_V1: u8 = 221;
const TYPE_FIXTURE_V2: u8 = 222;
const VERSION_FIXTURE_ROWS: TableName = TableName::new("version_fixture_rows");

const READ_AHEAD_WRITERS: &[FamilyWriter] = &[FamilyWriter {
    family: FAMILY,
    version: 1,
}];
const WRITE_V2_WRITERS: &[FamilyWriter] = &[FamilyWriter {
    family: FAMILY,
    version: 2,
}];
const PROTOCOL_1_FAMILIES: &[FamilyVersion] = &[
    FamilyVersion {
        family: FAMILY,
        version: 1,
    },
    FamilyVersion {
        family: OTHER_FAMILY,
        version: 1,
    },
];
const PROTOCOL_2_FAMILIES: &[FamilyVersion] = &[
    FamilyVersion {
        family: FAMILY,
        version: 2,
    },
    FamilyVersion {
        family: OTHER_FAMILY,
        version: 1,
    },
];
const FIXTURE_BUNDLES: &[ProtocolBundle] = &[
    ProtocolBundle {
        protocol: 1,
        families: PROTOCOL_1_FAMILIES,
    },
    ProtocolBundle {
        protocol: 2,
        families: PROTOCOL_2_FAMILIES,
    },
];
const FIXTURE_V1_PROJECTOR: FactVersionProjector =
    FactVersionProjector::new("fixture::v1::project_fixture_v1");
const FIXTURE_V2_PROJECTOR: FactVersionProjector =
    FactVersionProjector::new("fixture::v2::project_fixture_v2");
const FIXTURE_FACT_VERSIONS: &[FactVersionManifestEntry] = &[
    FactVersionManifestEntry {
        tag: TYPE_FIXTURE_V1,
        family: FAMILY,
        version: 1,
        active_from_protocol: 1,
        projector: FIXTURE_V1_PROJECTOR,
    },
    FactVersionManifestEntry {
        tag: TYPE_FIXTURE_V2,
        family: FAMILY,
        version: 2,
        active_from_protocol: 2,
        projector: FIXTURE_V2_PROJECTOR,
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixtureV1 {
    value: u64,
    has_authority: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixtureV2 {
    value: u64,
    bonus: u64,
    authority: FixtureAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureAuthority {
    Absent,
    Granted,
}

struct FixtureProjector;

fn decode_fixture_v1(fact: &Fact) -> Result<FixtureV1, String> {
    if fact.bytes.len() != 10 || fact.bytes[0] != TYPE_FIXTURE_V1 {
        return Err("fixture v1 bytes must be tag + authority + value".to_string());
    }
    Ok(FixtureV1 {
        has_authority: decode_authority(fact.bytes[1])?,
        value: u64::from_be_bytes(fact.bytes[2..10].try_into().unwrap()),
    })
}

fn decode_fixture_v2(fact: &Fact) -> Result<FixtureV2, String> {
    if fact.bytes.len() != 18 || fact.bytes[0] != TYPE_FIXTURE_V2 {
        return Err("fixture v2 bytes must be tag + authority + value + bonus".to_string());
    }
    Ok(FixtureV2 {
        authority: if decode_authority(fact.bytes[1])? {
            FixtureAuthority::Granted
        } else {
            FixtureAuthority::Absent
        },
        value: u64::from_be_bytes(fact.bytes[2..10].try_into().unwrap()),
        bonus: u64::from_be_bytes(fact.bytes[10..18].try_into().unwrap()),
    })
}

fn authenticate_fixture_v1(fact: &Fact, decoded: FixtureV1) -> Result<FixtureV1, String> {
    verify_fact_id(fact).map(|()| decoded)
}

fn authenticate_fixture_v2(fact: &Fact, decoded: FixtureV2) -> Result<FixtureV2, String> {
    verify_fact_id(fact).map(|()| decoded)
}

fn adapt_fixture_v1_to_v2(source: FixtureV1) -> Result<FixtureV2, String> {
    Ok(FixtureV2 {
        value: source.value,
        bonus: 0,
        authority: if source.has_authority {
            FixtureAuthority::Granted
        } else {
            FixtureAuthority::Absent
        },
    })
}

fn adapt_fixture_v2(source: FixtureV2) -> Result<FixtureV2, String> {
    Ok(source)
}

impl FixtureProjector {
    fn project(
        &self,
        fact: &Fact,
        semantic: FixtureV2,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(
            ProjectionOutput::new().row_mutation(RowMutation::InsertValues(
                topo::core::intents::TableInsert {
                    table: VERSION_FIXTURE_ROWS,
                    columns: &["fact_id", "value", "bonus", "authority"],
                    values: vec![
                        Value::Bytes(fact.id.to_vec()),
                        Value::U64(semantic.value),
                        Value::U64(semantic.bonus),
                        Value::Bool(matches!(semantic.authority, FixtureAuthority::Granted)),
                    ],
                },
            )),
        )
    }
}

#[test]
fn release_fixture_profiles_keep_write_activation_release_fixed() {
    let read_ahead = ReleaseProfile {
        release_id: "r2-read-ahead",
        read_head: 2,
        writers: READ_AHEAD_WRITERS,
    };
    let write_v2 = ReleaseProfile {
        release_id: "r3-write-v2",
        read_head: 2,
        writers: WRITE_V2_WRITERS,
    };

    let entries = [
        manifest_entry("r1", ProtocolRange::new(1, 1), 100),
        manifest_entry("r2", ProtocolRange::new(1, 2), 1_000),
    ];

    let before = compute_ceiling(&entries, TrustedTime::fresh(120), 20);
    assert_eq!(before.active_ceiling(), Ok(1));
    let before_bundle =
        bundle_for_protocol(FIXTURE_BUNDLES, before.active_ceiling().unwrap()).unwrap();
    assert_eq!(before_bundle.family_version(FAMILY), Some(1));
    assert_eq!(
        read_ahead.write_version_for_bundle(FAMILY, before_bundle),
        Ok(1)
    );
    assert_eq!(
        write_v2.write_version_for_bundle(FAMILY, before_bundle),
        Err(WriteVersionError::AboveCeiling {
            family: FAMILY,
            writer_version: 2,
            ceiling_version: 1,
        })
    );

    let after = compute_ceiling(&entries, TrustedTime::fresh(121), 20);
    assert_eq!(after.active_ceiling(), Ok(2));
    let after_bundle =
        bundle_for_protocol(FIXTURE_BUNDLES, after.active_ceiling().unwrap()).unwrap();
    assert_eq!(after_bundle.family_version(FAMILY), Some(2));
    assert_eq!(after_bundle.family_version(OTHER_FAMILY), Some(1));
    assert_eq!(
        read_ahead.write_version_for_bundle(FAMILY, after_bundle),
        Ok(1),
        "a read-ahead release keeps writing v1 after the ceiling permits v2"
    );
    assert_eq!(
        write_v2.write_version_for_bundle(FAMILY, after_bundle),
        Ok(2)
    );
}

#[test]
fn above_ceiling_received_fact_bytes_are_pending_until_admitted() {
    assert_eq!(
        classify_received_fact(Some(2), 1, true),
        IngressClassification::Pending(PendingReason::AboveCeiling {
            active_from_protocol: 2,
            ceiling: 1,
        })
    );
    assert_eq!(
        classify_received_fact(Some(2), 2, true),
        IngressClassification::Active
    );
}

#[test]
fn route_metadata_can_describe_deprecated_and_current_fact_versions() {
    let routes = [
        FactRoute {
            tag: TYPE_FIXTURE_V1,
            projector: project_fixture_v1,
            storage_requirement: StorageRequirement::MaintenanceBypass,
            projector_info: FIXTURE_V1_PROJECTOR.projector_info(),
        },
        FactRoute {
            tag: TYPE_FIXTURE_V2,
            projector: project_fixture_v2,
            storage_requirement: StorageRequirement::MaintenanceBypass,
            projector_info: FIXTURE_V2_PROJECTOR.projector_info(),
        },
    ];
    let route_manifest = routes.map(FactVersionRoute::from_fact_route);

    validate_fact_version_manifest(FIXTURE_FACT_VERSIONS, FIXTURE_BUNDLES, &route_manifest)
        .expect("fixture manifest matches bundles and route metadata");
    assert_eq!(
        active_from_protocol_for_tag(FIXTURE_FACT_VERSIONS, TYPE_FIXTURE_V1),
        Some(1)
    );
    assert_eq!(
        active_from_protocol_for_tag(FIXTURE_FACT_VERSIONS, TYPE_FIXTURE_V2),
        Some(2)
    );
}

#[test]
fn deprecated_v1_fact_projects_through_adapter_to_current_semantic() {
    let fact = fixture_v1_fact(7, false);
    let output = project_fixture_v1(&fact, &ProjectionContext::default()).expect("project v1");

    assert_eq!(
        projected_values(&output),
        (7, 0, false),
        "v1->v2 adapter must preserve absence instead of inventing authority"
    );
}

#[test]
fn current_v2_fact_projects_without_historical_adapter() {
    let fact = fixture_v2_fact(7, 11, true);
    let output = project_fixture_v2(&fact, &ProjectionContext::default()).expect("project v2");

    assert_eq!(projected_values(&output), (7, 11, true));
}

fn project_fixture_v1(
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let decoded = decode_fixture_v1(fact)?;
    let authenticated = authenticate_fixture_v1(fact, decoded)?;
    let semantic = adapt_fixture_v1_to_v2(authenticated)?;
    FixtureProjector.project(fact, semantic, context)
}

fn project_fixture_v2(
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let decoded = decode_fixture_v2(fact)?;
    let authenticated = authenticate_fixture_v2(fact, decoded)?;
    let semantic = adapt_fixture_v2(authenticated)?;
    FixtureProjector.project(fact, semantic, context)
}

fn fixture_v1_fact(value: u64, has_authority: bool) -> Fact {
    let mut bytes = vec![TYPE_FIXTURE_V1, u8::from(has_authority)];
    bytes.extend_from_slice(&value.to_be_bytes());
    Fact::new(FactScope::Global, 1, bytes)
}

fn fixture_v2_fact(value: u64, bonus: u64, has_authority: bool) -> Fact {
    let mut bytes = vec![TYPE_FIXTURE_V2, u8::from(has_authority)];
    bytes.extend_from_slice(&value.to_be_bytes());
    bytes.extend_from_slice(&bonus.to_be_bytes());
    Fact::new(FactScope::Global, 1, bytes)
}

fn manifest_entry(
    release_id: &'static str,
    supported_protocol: ProtocolRange,
    expires_at_ms: u64,
) -> ReleaseManifestEntry {
    ReleaseManifestEntry {
        release_id: release_id.to_string(),
        platform: "desktop".to_string(),
        supported_protocol,
        expires_at_ms,
        security_deprecated: false,
    }
}

fn decode_authority(byte: u8) -> Result<bool, String> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("fixture authority byte must be 0 or 1".to_string()),
    }
}

fn projected_values(output: &ProjectionOutput) -> (u64, u64, bool) {
    assert_eq!(output.effects.row_mutations.len(), 1);
    let RowMutation::InsertValues(row) = &output.effects.row_mutations[0] else {
        panic!("fixture projector emits one typed row")
    };
    assert_eq!(row.table, VERSION_FIXTURE_ROWS);

    let Value::U64(value) = row.values[1] else {
        panic!("fixture value is u64")
    };
    let Value::U64(bonus) = row.values[2] else {
        panic!("fixture bonus is u64")
    };
    let Value::Bool(authority) = row.values[3] else {
        panic!("fixture authority is bool")
    };
    (value, bonus, authority)
}
