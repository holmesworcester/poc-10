//! Local protocol update facts and recurring release-version checks.
//!
//! This module owns the release marker side of protocol versioning. The daemon's
//! recurring `check_version` intent compares the stored marker with
//! `CURRENT_PROTOCOL_VERSION`. A mismatch emits a priority local update fact.
//! Projecting that update fact requests the generic rebuild effect, which clears
//! schema-declared resettable state and requeues retained facts in replay mode,
//! then records the new marker as protocol state.
//!
//! This is deliberately not the same as a projector/query storage requirement.
//! Per-family projector and query guards are safety contracts for reading or
//! writing materialized tables. The release marker is only the protocol-owned
//! trigger that decides when to emit the update fact that can make those guarded
//! paths safe again.

use crate::core::cli::{encode_hex_32, CliOutput};
use crate::core::command::{AuthoredFacts, CommandClock};
use crate::core::db::{Db, TableInsert, TableName, TypedTableSchema, Value};
use crate::core::effects::{RuntimeEffects, StorageRequirement};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::{HandlerContext, HandlerResult, Intent, IntentHandler, IntentKind};
use crate::core::project_fact::{
    verify_fact_id, FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::core::runtime::RecurringIntentContext;
use crate::core::wire;
use rusqlite::{OptionalExtension, Row};

pub const CURRENT_PROTOCOL_VERSION: u32 = 1;
pub const TYPE_VERSIONING_UPDATE: u8 = 175;
pub const UPDATE_FACT_BYTES: usize = 1 + 4 + 8;
pub const CHECK_VERSION: &str = "check_version";

pub const PROTOCOL_VERSION_ROWS: TableName = TableName::new("protocol_version_rows");
pub const PROTOCOL_VERSION_COLUMNS: &[&str] =
    &["update_fact_id", "protocol_version", "applied_at_ms"];
pub const PROTOCOL_VERSION_KEY_COLUMNS: &[&str] = &["update_fact_id"];
pub const PROTOCOL_VERSION_TABLE: TypedTableSchema = TypedTableSchema {
    table: PROTOCOL_VERSION_ROWS,
    columns: PROTOCOL_VERSION_COLUMNS,
    key_columns: PROTOCOL_VERSION_KEY_COLUMNS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateFact {
    pub protocol_version: u32,
    pub applied_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRow {
    pub update_fact_id: FactId,
    pub protocol_version: u32,
    pub applied_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateReceipt {
    pub update_fact_id: FactId,
    pub protocol_version: u32,
    pub applied_at_ms: u64,
}

pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("versioning::update::UpdateProjector");

pub const STORAGE_REQUIREMENT: StorageRequirement = StorageRequirement::MaintenanceBypass;

#[derive(Debug, Default)]
pub struct UpdateProjector;

impl UpdateProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for UpdateProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let update = authenticate(fact, decode_update_fact(fact.body())?, context)?;
        if context.is_replay() {
            return Ok(ProjectionOutput::new());
        }

        Ok(ProjectionOutput::new()
            .rebuild_derived_state()
            .row_mutation(crate::core::intents::RowMutation::InsertValues(
                version_row(fact.id, update),
            )))
    }
}

pub fn author_update(clock: &dyn CommandClock) -> Result<AuthoredFacts<UpdateReceipt>, String> {
    let applied_at_ms = clock.next_timestamp();
    let fact = update_fact(UpdateFact {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        applied_at_ms,
    })?;
    Ok(AuthoredFacts::new(UpdateReceipt {
        update_fact_id: fact.id,
        protocol_version: CURRENT_PROTOCOL_VERSION,
        applied_at_ms,
    })
    .with_facts(vec![fact]))
}

pub fn update_output(receipt: &UpdateReceipt, pending_projection: usize) -> CliOutput {
    CliOutput::lines(vec![
        format!("update_fact: {}", encode_hex_32(&receipt.update_fact_id)),
        format!("protocol_version: {}", receipt.protocol_version),
        format!("applied_at_ms: {}", receipt.applied_at_ms),
        format!("pending_projection: {pending_projection}"),
    ])
}

pub fn update_fact(update: UpdateFact) -> Result<Fact, String> {
    Ok(Fact::new(
        FactScope::Local,
        update.applied_at_ms,
        encode_update_fact(update)?,
    ))
}

pub fn current_version(store: &Db) -> Result<Option<VersionRow>, String> {
    store
        .conn()
        .query_row(
            "SELECT update_fact_id, protocol_version, applied_at_ms
             FROM protocol_version_rows
             ORDER BY applied_at_ms DESC, update_fact_id DESC
             LIMIT 1",
            [],
            decode_version_row,
        )
        .optional()
        .map_err(|err| format!("read projected protocol version: {err}"))
}

pub fn storage_ready(store: &Db) -> Result<bool, String> {
    if rebuild_work_pending(store)? {
        return Ok(false);
    }
    match current_version(store)? {
        Some(row) => Ok(row.protocol_version == CURRENT_PROTOCOL_VERSION),
        None => retained_fact_count(store).map(|facts| facts == 0),
    }
}

pub fn ensure_storage_ready(store: &Db) -> Result<(), String> {
    if storage_ready(store)? {
        return Ok(());
    }
    let stored = current_version(store)?
        .map(|row| row.protocol_version.to_string())
        .unwrap_or_else(|| "missing".to_string());
    Err(format!(
        "protocol update required: stored_version={stored} current_version={CURRENT_PROTOCOL_VERSION}; start the daemon or run `update` and let projection drain"
    ))
}

pub fn require_storage_requirement(
    store: &Db,
    requirement: StorageRequirement,
) -> Result<(), String> {
    match requirement {
        StorageRequirement::Current(version) => require_storage_version(store, version),
        StorageRequirement::MaintenanceBypass => Ok(()),
    }
}

pub fn require_storage_version(store: &Db, expected: u32) -> Result<(), String> {
    match current_version(store)? {
        Some(row) if row.protocol_version == expected => Ok(()),
        Some(row) => Err(format!(
            "storage version mismatch: required_version={expected} stored_version={}",
            row.protocol_version
        )),
        None => Err(format!(
            "storage version mismatch: required_version={expected} stored_version=missing"
        )),
    }
}

pub fn build_check_version_intent(
    store: &Db,
    context: RecurringIntentContext,
) -> Result<Option<Intent>, String> {
    if current_version(store)?.is_some_and(|row| row.protocol_version == CURRENT_PROTOCOL_VERSION) {
        return Ok(None);
    }
    Ok(Some(check_version_intent(context.now_ms)))
}

fn check_version_intent(now_ms: u64) -> Intent {
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&CURRENT_PROTOCOL_VERSION.to_be_bytes());
    payload.extend_from_slice(&now_ms.to_be_bytes());
    let mut key = b"v".to_vec();
    key.extend_from_slice(&CURRENT_PROTOCOL_VERSION.to_be_bytes());
    key.extend_from_slice(&now_ms.to_be_bytes());
    Intent::new(
        IntentKind::new(CHECK_VERSION).expect("valid check_version kind"),
        key,
        payload,
    )
}

fn decode_check_version(intent: &Intent) -> Result<UpdateFact, String> {
    if intent.kind.as_str() != CHECK_VERSION {
        return Err("expected check_version intent".to_string());
    }
    wire::expect_len(&intent.payload, 12).map_err(wire_err)?;
    let protocol_version = wire::take_u32be(&intent.payload[0..4]).map_err(wire_err)?;
    let applied_at_ms = wire::take_u64be(&intent.payload[4..12]).map_err(wire_err)?;
    Ok(UpdateFact {
        protocol_version,
        applied_at_ms,
    })
}

#[derive(Debug, Clone, Default)]
pub struct CheckVersionHandler;

impl CheckVersionHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for CheckVersionHandler {
    fn input_fact_ids(
        &self,
        intent: &Intent,
    ) -> Result<Vec<crate::core::intents::HandlerFactId>, String> {
        decode_check_version(intent)?;
        Ok(Vec::new())
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult {
        let update = decode_check_version(intent)?;
        if context.is_replay() {
            return Ok(RuntimeEffects::new());
        }
        if current_version(context.db()?)?
            .is_some_and(|row| row.protocol_version == CURRENT_PROTOCOL_VERSION)
        {
            return Ok(RuntimeEffects::new());
        }
        Ok(RuntimeEffects::new().priority_fact(update_fact(update)?))
    }
}

pub fn encode_update_fact(update: UpdateFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; UPDATE_FACT_BYTES];
    wire::put_u8(TYPE_VERSIONING_UPDATE, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u32be(update.protocol_version, &mut out[1..5]).map_err(wire_err)?;
    wire::put_u64be(update.applied_at_ms, &mut out[5..13]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_update_fact(bytes: &[u8]) -> Result<UpdateFact, String> {
    wire::expect_len(bytes, UPDATE_FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_VERSIONING_UPDATE {
        return Err("expected versioning update fact".to_string());
    }
    let protocol_version = wire::take_u32be(&bytes[1..5]).map_err(wire_err)?;
    let applied_at_ms = wire::take_u64be(&bytes[5..13]).map_err(wire_err)?;
    Ok(UpdateFact {
        protocol_version,
        applied_at_ms,
    })
}

pub fn authenticate(
    fact: &Fact,
    decoded: UpdateFact,
    _context: &ProjectionContext,
) -> Result<UpdateFact, String> {
    verify_fact_id(fact)?;
    if fact.scope != FactScope::Local {
        return Err("versioning update must be a local fact".to_string());
    }
    Ok(decoded)
}

pub fn version_row(update_fact_id: FactId, update: UpdateFact) -> TableInsert {
    PROTOCOL_VERSION_TABLE.insert(vec![
        Value::Bytes(update_fact_id.to_vec()),
        Value::U64(u64::from(update.protocol_version)),
        Value::U64(update.applied_at_ms),
    ])
}

fn decode_version_row(row: &Row<'_>) -> rusqlite::Result<VersionRow> {
    let id = row.get::<_, Vec<u8>>(0)?;
    let update_fact_id = id.try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName("protocol version fact id is not 32 bytes".into())
    })?;
    let protocol_version = u32::try_from(row.get::<_, i64>(1)?).map_err(|_| {
        rusqlite::Error::InvalidParameterName("protocol version exceeds u32".into())
    })?;
    let applied_at_ms = u64::try_from(row.get::<_, i64>(2)?).map_err(|_| {
        rusqlite::Error::InvalidParameterName("protocol version applied_at_ms is negative".into())
    })?;
    Ok(VersionRow {
        update_fact_id,
        protocol_version,
        applied_at_ms,
    })
}

fn retained_fact_count(store: &Db) -> Result<usize, String> {
    store
        .table_row_count(crate::core::schema::FACTS)
        .map_err(|err| format!("count retained facts for protocol version guard: {err}"))
}

fn rebuild_work_pending(store: &Db) -> Result<bool, String> {
    let pending = store
        .conn()
        .query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM pending_projection WHERE replay != 0
                 UNION ALL
                 SELECT 1 FROM intents WHERE replay != 0
                 UNION ALL
                 SELECT 1 FROM local_intents WHERE replay != 0
             )",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|err| format!("check rebuild work: {err}"))?;
    Ok(pending != 0)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::command::FnClock;
    use crate::core::intents::IntentHandler;
    use crate::core::runtime::Runtime;
    use crate::protocol::app::MATCH_RUNTIME;
    use rusqlite::params;

    fn replace_stored_version_for_test(store: &Db, protocol_version: u32) {
        store
            .write_transaction(|tx| {
                tx.conn().execute("DELETE FROM protocol_version_rows", [])?;
                tx.conn().execute(
                    "INSERT INTO protocol_version_rows
                        (update_fact_id, protocol_version, applied_at_ms)
                     VALUES (?1, ?2, ?3)",
                    params![vec![1_u8; 32], i64::from(protocol_version), 1_i64],
                )?;
                Ok(())
            })
            .expect("replace stored protocol version");
    }

    #[test]
    fn update_fact_roundtrips_fixed_width() {
        let update = UpdateFact {
            protocol_version: 7,
            applied_at_ms: 123,
        };
        let encoded = encode_update_fact(update).expect("encode");
        assert_eq!(encoded.len(), UPDATE_FACT_BYTES);
        assert_eq!(decode_update_fact(&encoded).expect("decode"), update);
    }

    #[test]
    fn author_update_creates_local_fact() {
        let output = author_update(&FnClock(|| 44)).expect("author update");
        let (_receipt, facts) = output.into_parts();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].scope, FactScope::Local);
        assert_eq!(
            decode_update_fact(facts[0].body())
                .expect("decode")
                .protocol_version,
            CURRENT_PROTOCOL_VERSION
        );
    }

    #[test]
    fn projector_records_version_and_requests_rebuild_only_live() {
        let output = author_update(&FnClock(|| 44)).expect("author update");
        let (_receipt, facts) = output.into_parts();
        let fact = &facts[0];
        let live = UpdateProjector::new()
            .project(fact, &ProjectionContext::default())
            .expect("project live update");
        assert!(live.effects.rebuild_derived_state);
        assert_eq!(live.effects.row_mutations.len(), 1);

        let replay = UpdateProjector::new()
            .project(
                fact,
                &ProjectionContext::default()
                    .with_mode(crate::core::project_fact::ProjectionMode::Replay),
            )
            .expect("project replay update");
        assert!(replay.effects.is_empty());
    }

    #[test]
    fn storage_guard_waits_for_update_projection_and_rebuild_drain() {
        let mut runtime = Runtime::open_memory(&MATCH_RUNTIME).expect("runtime");
        assert!(
            storage_ready(runtime.db()).expect("empty db guard"),
            "fresh databases seed the current version marker"
        );

        replace_stored_version_for_test(runtime.db(), CURRENT_PROTOCOL_VERSION - 1);
        let update = update_fact(UpdateFact {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            applied_at_ms: 44,
        })
        .expect("update fact");
        runtime.submit_fact(update);
        assert!(
            !storage_ready(runtime.db()).expect("stale version marker"),
            "stale storage requires update"
        );

        runtime
            .drain_durable_projection(1)
            .expect("project live update");
        assert_eq!(
            current_version(runtime.db())
                .expect("current version")
                .expect("version row")
                .protocol_version,
            CURRENT_PROTOCOL_VERSION
        );
        assert!(
            !storage_ready(runtime.db()).expect("rebuild pending"),
            "the version row alone is not enough while replay-mode rebuild work is queued"
        );

        runtime
            .drain_durable_projection(8)
            .expect("drain replay update no-op");
        assert!(
            storage_ready(runtime.db()).expect("rebuilt guard"),
            "storage becomes ready only after replay-mode rebuild work drains"
        );
    }

    #[test]
    fn check_version_handler_emits_priority_update_fact() {
        let runtime = Runtime::open_memory(&MATCH_RUNTIME).expect("runtime");
        replace_stored_version_for_test(runtime.db(), CURRENT_PROTOCOL_VERSION - 1);
        let intent = check_version_intent(55);
        let context = HandlerContext::new().with_db(runtime.db());
        let output = CheckVersionHandler::new()
            .handle(&intent, &context)
            .expect("handle check_version");
        assert!(output.facts.is_empty());
        assert_eq!(output.priority_facts.len(), 1);
        assert_eq!(
            decode_update_fact(output.priority_facts[0].body())
                .expect("decode update")
                .protocol_version,
            CURRENT_PROTOCOL_VERSION
        );
    }
}
