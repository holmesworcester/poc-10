//! Synthetic release-fixture tests for protocol versioning.
//!
//! These tests avoid real protocol fact families so they can run while the
//! family role-file cutover is in progress. The fixture models the important
//! behavior: a read-ahead release can decode/authenticate/adapt old and new
//! fact bytes, while write activation remains fixed by the release profile.

use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{RowMutation, Value};
use topo::core::pipeline::{
    project_staged, Adapter, Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    ProjectionOutput, SemanticProjector,
};
use topo::core::pipeline::{verify_fact_id, FactPipeline, FactRoute};
use topo::core::store::TableName;
use topo::core::versioning::{
    classify_received_fact, compute_ceiling, FamilyWriter, IngressClassification, PendingReason,
    ProtocolRange, ReleaseManifestEntry, ReleaseProfile, TrustedTime, WriteVersionError,
};

const FAMILY: &str = "version_fixture";
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

struct FixtureV1Codec;
struct FixtureV2Codec;
struct FixtureV1Authenticator;
struct FixtureV2Authenticator;
struct FixtureV1ToV2Adapter;
struct FixtureV2IdentityAdapter;
struct FixtureProjector;

impl FactCodec for FixtureV1Codec {
    type Payload = FixtureV1;

    fn decode_fact(fact: &Fact) -> Result<Self::Payload, String> {
        if fact.bytes.len() != 10 || fact.bytes[0] != TYPE_FIXTURE_V1 {
            return Err("fixture v1 bytes must be tag + authority + value".to_string());
        }
        Ok(FixtureV1 {
            has_authority: decode_authority(fact.bytes[1])?,
            value: u64::from_be_bytes(fact.bytes[2..10].try_into().unwrap()),
        })
    }
}

impl FactCodec for FixtureV2Codec {
    type Payload = FixtureV2;

    fn decode_fact(fact: &Fact) -> Result<Self::Payload, String> {
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
}

impl DecodedAuthenticator<FixtureV1Codec> for FixtureV1Authenticator {
    type Authenticated = FixtureV1;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        decoded: FixtureV1,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, verify_fact_id(fact).map(|()| decoded))
    }
}

impl DecodedAuthenticator<FixtureV2Codec> for FixtureV2Authenticator {
    type Authenticated = FixtureV2;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        decoded: FixtureV2,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, verify_fact_id(fact).map(|()| decoded))
    }
}

impl Adapter for FixtureV1ToV2Adapter {
    type Source = FixtureV1;
    type Semantic = FixtureV2;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
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
}

impl Adapter for FixtureV2IdentityAdapter {
    type Source = FixtureV2;
    type Semantic = FixtureV2;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}

impl SemanticProjector<FixtureV2> for FixtureProjector {
    fn project_semantic(
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
    assert_eq!(read_ahead.write_version(FAMILY, 1), Ok(1));
    assert_eq!(
        write_v2.write_version(FAMILY, 1),
        Err(WriteVersionError::AboveCeiling {
            family: FAMILY,
            writer_version: 2,
            ceiling: 1,
        })
    );

    let after = compute_ceiling(&entries, TrustedTime::fresh(121), 20);
    assert_eq!(after.active_ceiling(), Ok(2));
    assert_eq!(
        read_ahead.write_version(FAMILY, 2),
        Ok(1),
        "a read-ahead release keeps writing v1 after the ceiling permits v2"
    );
    assert_eq!(write_v2.write_version(FAMILY, 2), Ok(2));
}

#[test]
fn above_ceiling_received_fact_bytes_are_pending_until_admitted() {
    assert_eq!(
        classify_received_fact(Some(2), 1, true),
        IngressClassification::Pending(PendingReason::AboveCeiling {
            intro_version: 2,
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
            pipeline: FactPipeline::Staged {
                decode: "fixture::v1::decode::Codec",
                authenticate: "fixture::v1::authenticate::Authenticator",
                adapt: "fixture::v2::adapt::FromV1",
                project: "fixture::v2::project::Projector",
            },
            replayed: true,
        },
        FactRoute {
            tag: TYPE_FIXTURE_V2,
            projector: project_fixture_v2,
            pipeline: FactPipeline::Staged {
                decode: "fixture::v2::decode::Codec",
                authenticate: "fixture::v2::authenticate::Authenticator",
                adapt: "fixture::v2::adapt::Identity",
                project: "fixture::v2::project::Projector",
            },
            replayed: true,
        },
    ];

    let FactPipeline::Staged { adapt, project, .. } = routes[0].pipeline else {
        panic!("v1 route should be staged")
    };
    assert_eq!(adapt, "fixture::v2::adapt::FromV1");
    assert_eq!(project, "fixture::v2::project::Projector");
    assert!(routes.iter().all(|route| route.replayed));
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
    project_staged::<FixtureV1Codec, FixtureV1Authenticator, FixtureV1ToV2Adapter, _>(
        &FixtureProjector,
        fact,
        context,
    )
}

fn project_fixture_v2(
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    project_staged::<FixtureV2Codec, FixtureV2Authenticator, FixtureV2IdentityAdapter, _>(
        &FixtureProjector,
        fact,
        context,
    )
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
