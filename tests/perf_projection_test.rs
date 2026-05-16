//! Ignored end-to-end projection perf tests for target content facts.
//!
//! These tests are intentionally not microbenchmarks. They prebuild target
//! message, file, and file-slice facts, then drive them through the target
//! `WakeLoop` plus atomic row intents. The timed path therefore excludes fact
//! construction and includes target projector dispatch, context matching, and
//! row writes.

use std::time::{Duration, Instant};

use topo::core::crypto;
use topo::core::facts::{Fact, FactId};
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::schema_dsl::FACTS_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::{DrainReport, WakeLoop};
use topo::protocol::facts::content::file::fact::ContentFileFact;
use topo::protocol::facts::content::file::layout as file_layout;
use topo::protocol::facts::content::file_slice::fact::ContentFileSliceFact;
use topo::protocol::facts::content::file_slice::{layout as slice_layout, rows as slice_rows};
use topo::protocol::facts::content::message::fact::{unix_minute_for, ContentMessageFact};
use topo::protocol::facts::content::message::layout as message_layout;
use topo::protocol::matchers as file_context;
use topo::protocol::matchers as message_context;
use topo::protocol::matchers::ExactSelectorMatcher;

const MIB: usize = 1024 * 1024;
const MESSAGE_BATCH: usize = 4096;
const FILE_SLICE_BYTES: usize = MIB;
const FILE_SLICE_BATCH: u32 = 16;

struct PerfFixture {
    store: Store,
    bus: WakeLoop,
    workspace_id: FactId,
    author_user_id: FactId,
    frontier_id: FactId,
    next_timestamp: u64,
}

impl PerfFixture {
    fn new() -> Self {
        Self {
            store: Store::open_memory_with_schema_sources(&[FACTS_SCHEMA_SOURCE])
                .expect("open target schema"),
            bus: WakeLoop::new(),
            workspace_id: [1; 32],
            author_user_id: [2; 32],
            frontier_id: [3; 32],
            next_timestamp: 10_000,
        }
    }

    fn next_message(&mut self, sequence: usize) -> Fact {
        let created_at_ms = self.take_timestamp();
        let message = ContentMessageFact {
            workspace_id: self.workspace_id,
            author_user_id: self.author_user_id,
            created_at_ms,
            frontier_id: self.frontier_id,
            minute: unix_minute_for(created_at_ms),
            leaf_id: id_from_parts(b"message leaf", sequence as u64),
            sealed_body_ref: id_from_parts(b"sealed body", sequence as u64),
        };
        Fact::new(
            message_context::workspace_scope(self.workspace_id),
            created_at_ms,
            message_layout::encode_fact(&message).expect("encode message"),
        )
    }

    fn next_file(
        &mut self,
        message_id: FactId,
        file_id: FactId,
        blob_bytes: usize,
        total_slices: u32,
    ) -> Fact {
        let created_at_ms = self.take_timestamp();
        let file = ContentFileFact {
            workspace_id: self.workspace_id,
            created_at_ms,
            message_id,
            author_user_id: self.author_user_id,
            file_id,
            blob_bytes: blob_bytes as u64,
            total_slices,
            slice_bytes: FILE_SLICE_BYTES as u32,
            root_hash: derive_root_hash(file_id, blob_bytes as u64, total_slices),
            sealed_metadata: format!("perf-{blob_bytes}b.bin\x00application/octet-stream")
                .into_bytes(),
        };
        Fact::new(
            message_context::workspace_scope(self.workspace_id),
            created_at_ms,
            file_layout::encode_fact(&file).expect("encode file"),
        )
    }

    fn next_slice(&mut self, file_id: FactId, slice_index: u32, blob_bytes: usize) -> Fact {
        let start = slice_index as usize * FILE_SLICE_BYTES;
        let plaintext_len = (blob_bytes - start).min(FILE_SLICE_BYTES);
        let mut ciphertext = vec![0; plaintext_len + crypto::XCHACHA20_POLY1305_TAG_BYTES];
        fill_payload_slice(&mut ciphertext, slice_index);
        let slice = ContentFileSliceFact {
            workspace_id: self.workspace_id,
            created_at_ms: self.take_timestamp(),
            file_id,
            slice_index,
            ciphertext,
        };
        Fact::new(
            message_context::workspace_scope(self.workspace_id),
            slice.created_at_ms,
            slice_layout::encode_fact(&slice).expect("encode slice"),
        )
    }

    fn take_timestamp(&mut self) -> u64 {
        let timestamp = self.next_timestamp;
        self.next_timestamp = self.next_timestamp.saturating_add(1);
        timestamp
    }

    fn project_facts(&mut self, facts: Vec<Fact>) -> DrainReport {
        for fact in facts {
            self.bus.submit_fact(fact);
        }
        let message_matcher = ExactSelectorMatcher::new(message_context::message_role());
        let file_matcher = ExactSelectorMatcher::new(file_context::file_role());
        self.bus
            .drain_applying_atomic_rows(
                &ProjectionPerfProjector,
                &[&message_matcher, &file_matcher],
                &self.store,
                &[
                    topo::protocol::facts::content::message::rows::CONTENT_MESSAGE_ROWS,
                    topo::protocol::facts::content::file::rows::FILE_ROWS,
                    slice_rows::FILE_SLICE_ROWS,
                ],
                usize::MAX,
            )
            .expect("project target facts")
    }

    fn message_exists(&self, message_id: FactId) -> bool {
        let key = topo::protocol::facts::content::message::rows::content_message_key(
            self.workspace_id,
            message_id,
        );
        self.store
            .table_row(
                topo::protocol::facts::content::message::rows::CONTENT_MESSAGE_ROWS,
                &key,
            )
            .expect("load message row")
            .is_some()
    }

    fn file_exists(&self, file_fact_id: FactId) -> bool {
        let key = topo::protocol::facts::content::file::rows::content_file_key(
            &self.workspace_id,
            &file_fact_id,
        );
        self.store
            .table_row(topo::protocol::facts::content::file::rows::FILE_ROWS, &key)
            .expect("load file row")
            .is_some()
    }

    fn file_slice_exists(&self, file_id: FactId, slice_index: u32) -> bool {
        let key = slice_rows::content_file_slice_key(&self.workspace_id, &file_id, slice_index);
        self.store
            .table_row(slice_rows::FILE_SLICE_ROWS, &key)
            .expect("load file slice row")
            .is_some()
    }
}

/// Invariant: 1k prebuilt target messages remain projectable without timing
/// command-side fact construction.
#[test]
#[ignore]
fn messages_1k_projection_perf() {
    run_message_projection_perf(1_000);
}

/// Invariant: 10k target messages remain projectable, and one additional
/// already-created message projects against the populated workspace.
#[test]
#[ignore]
fn messages_10k_projection_perf() {
    run_message_projection_perf(10_000);
}

/// Invariant: 100k target messages keep the same projection contract as the
/// small case; the measurement catches throughput cliffs from context/index
/// maintenance and row writes.
#[test]
#[ignore]
fn messages_100k_projection_perf() {
    run_message_projection_perf(100_000);
}

/// Invariant: 500k target messages are still a replayable fact history, and
/// the latest-message projection path stays measurable after that much prior
/// content has been applied.
#[test]
#[ignore]
fn messages_500k_projection_perf() {
    run_message_projection_perf(500_000);
}

/// Invariant: one 10 MiB file uses the target message + descriptor + slice
/// fact shape, and slice rows become visible only through target context.
#[test]
#[ignore]
fn file_10mib_projection_perf() {
    run_file_projection_perf(10);
}

/// Invariant: one 100 MiB file keeps file throughput dominated by bounded
/// file/slice facts rather than by event construction.
#[test]
#[ignore]
fn file_100mib_projection_perf() {
    run_file_projection_perf(100);
}

/// Invariant: one 500 MiB file remains projectable as fixed-size slice facts,
/// giving an upper-scale MB/s check for context matching and row writes.
#[test]
#[ignore]
fn file_500mib_projection_perf() {
    run_file_projection_perf(500);
}

fn run_message_projection_perf(count: usize) {
    assert!(count > 0, "message perf needs at least one message");
    let mut fixture = PerfFixture::new();
    let mut projection_elapsed = Duration::ZERO;
    let mut projected_events = 0usize;

    if count > 1 {
        let prefix = project_message_prefix(&mut fixture, count - 1);
        projected_events += prefix.projected_events;
        projection_elapsed += prefix.elapsed;
    }

    let latest = fixture.next_message(count - 1);
    let latest_message_id = latest.id;
    let latest_started = Instant::now();
    let latest_report = fixture.project_facts(vec![latest]);
    let latest_elapsed = latest_started.elapsed();
    projection_elapsed += latest_elapsed;
    projected_events += latest_report.intents;

    assert_eq!(latest_report.intents, 1);
    assert_eq!(projected_events, count);
    assert!(fixture.message_exists(latest_message_id));

    println!(
        "perf messages count={} project_ms={:.3} project_messages_s={:.2} latest_project_ms={:.3}",
        count,
        millis(projection_elapsed),
        rate(count, projection_elapsed),
        millis(latest_elapsed)
    );
}

struct TimedProjection {
    projected_events: usize,
    elapsed: Duration,
}

fn project_message_prefix(fixture: &mut PerfFixture, count: usize) -> TimedProjection {
    let mut produced = 0usize;
    let mut projected = 0usize;
    let mut elapsed = Duration::ZERO;
    while produced < count {
        let batch_len = (count - produced).min(MESSAGE_BATCH);
        let mut facts = Vec::with_capacity(batch_len);
        let mut latest_message_id = [0u8; 32];
        for _ in 0..batch_len {
            let message = fixture.next_message(produced);
            latest_message_id = message.id;
            facts.push(message);
            produced += 1;
        }
        let started = Instant::now();
        let report = fixture.project_facts(facts);
        elapsed += started.elapsed();
        assert_eq!(report.intents, batch_len);
        assert!(fixture.message_exists(latest_message_id));
        projected += report.intents;
    }
    TimedProjection {
        projected_events: projected,
        elapsed,
    }
}

fn run_file_projection_perf(mib: usize) {
    assert!(mib > 0, "file perf needs a non-empty payload");
    let mut fixture = PerfFixture::new();
    let mut projection_elapsed = Duration::ZERO;
    let blob_bytes = mib * MIB;
    let total_slices = blob_bytes.div_ceil(FILE_SLICE_BYTES) as u32;

    let parent = fixture.next_message(0);
    let message_id = parent.id;
    let file_id = derive_file_id(&fixture, message_id, blob_bytes as u64);
    let file = fixture.next_file(message_id, file_id, blob_bytes, total_slices);
    let file_fact_id = file.id;

    let started = Instant::now();
    let root_report = fixture.project_facts(vec![parent, file]);
    projection_elapsed += started.elapsed();
    assert_eq!(root_report.intents, 2);
    assert!(fixture.message_exists(message_id));
    assert!(fixture.file_exists(file_fact_id));
    let mut projected_events = root_report.intents;

    let mut slice_index = 0u32;
    while slice_index < total_slices {
        let end = (slice_index + FILE_SLICE_BATCH).min(total_slices);
        let mut batch = Vec::with_capacity((end - slice_index) as usize);
        while slice_index < end {
            batch.push(fixture.next_slice(file_id, slice_index, blob_bytes));
            slice_index += 1;
        }
        let batch_len = batch.len();
        let started = Instant::now();
        let report = fixture.project_facts(batch);
        projection_elapsed += started.elapsed();
        assert_eq!(report.intents, batch_len);
        projected_events += report.intents;
    }

    assert!(fixture.file_slice_exists(file_id, total_slices - 1));
    assert_eq!(projected_events, 2 + total_slices as usize);

    println!(
        "perf file mib={} bytes={} slices={} project_ms={:.3} project_mib_s={:.2} facts={}",
        mib,
        blob_bytes,
        total_slices,
        millis(projection_elapsed),
        rate(blob_bytes / MIB, projection_elapsed),
        projected_events
    );
}

#[derive(Debug, Clone, Copy)]
struct ProjectionPerfProjector;

impl Projector for ProjectionPerfProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(message_layout::TYPE_CONTENT_MESSAGE) => {
                topo::protocol::facts::content::message::project::ContentMessageProjector::new()
                    .project(fact, context)
            }
            Some(file_layout::TYPE_CONTENT_FILE) => {
                topo::protocol::facts::content::file::project::ContentFileProjector::new()
                    .project(fact, context)
            }
            Some(slice_layout::TYPE_CONTENT_FILE_SLICE) => {
                topo::protocol::facts::content::file_slice::project::ContentFileSliceProjector::new(
                )
                .project(fact, context)
            }
            _ => Err("unknown projection perf fact".to_string()),
        }
    }
}

fn derive_file_id(fixture: &PerfFixture, message_id: FactId, blob_bytes: u64) -> FactId {
    let mut input = Vec::with_capacity(32 + 32 + 8);
    input.extend_from_slice(&fixture.workspace_id);
    input.extend_from_slice(&message_id);
    input.extend_from_slice(&blob_bytes.to_be_bytes());
    crypto::hash(&input)
}

fn derive_root_hash(file_id: FactId, blob_bytes: u64, total_slices: u32) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 8 + 4);
    input.extend_from_slice(&file_id);
    input.extend_from_slice(&blob_bytes.to_be_bytes());
    input.extend_from_slice(&total_slices.to_be_bytes());
    crypto::hash(&input)
}

fn id_from_parts(domain: &[u8], value: u64) -> FactId {
    let mut input = Vec::with_capacity(domain.len() + 8);
    input.extend_from_slice(domain);
    input.extend_from_slice(&value.to_be_bytes());
    crypto::hash(&input)
}

fn fill_payload_slice(out: &mut [u8], slice_number: u32) {
    let seed = slice_number.to_le_bytes();
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = seed[idx % seed.len()]
            .wrapping_add(idx as u8)
            .rotate_left((idx % 7) as u32);
    }
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn rate(units: usize, duration: Duration) -> f64 {
    units as f64 / duration.as_secs_f64().max(f64::EPSILON)
}
