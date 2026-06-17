//! Replay diagnostics and state summaries.
//!
//! Replay-check runs replay in multiple orders on scratch databases and compares
//! their derived state. This module owns the diagnostic table hashing used by
//! `state-summary` and replay-check reports. Primary replay stays in
//! `replay.rs`; whole-table scans belong here because they are diagnostics, not
//! runtime query helpers.

use crate::core::db::{quoted_identifier_list, quoted_table_name, Db, TableName};
use rusqlite::types::ValueRef;

/// One hashed state area in a [`StateSummary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AreaSummary {
    /// Table name owning this area.
    pub area: String,
    /// Canonical hash of the area's rows.
    pub hash: [u8; 32],
    /// Row count in the area.
    pub count: usize,
}

/// A stable, order-independent digest of replay-relevant state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSummary {
    /// Overall digest combining every per-area hash and count.
    pub state_hash: [u8; 32],
    /// Per-area hashes and counts, ordered by area name.
    pub areas: Vec<AreaSummary>,
}

/// Canonical digest of one schema-declared replay summary table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSummary {
    /// Table name owning this area.
    pub table: String,
    /// Canonical hash of the table's rows.
    pub hash: [u8; 32],
    /// Row count in the table.
    pub count: usize,
}

/// One replay-check pass: a named replay plan and the state it reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCheckPass {
    /// Pass name (canonical, idempotent, reverse, scramble-N).
    pub name: String,
    /// State digest this pass reached on its scratch copy.
    pub state_hash: [u8; 32],
    /// Per-area differences from the canonical pass, if any.
    pub area_diffs: Vec<String>,
}

/// Result of comparing every replay-check pass against the canonical pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCheckReport {
    /// State digest of the canonical pass; every pass should match it.
    pub canonical_hash: [u8; 32],
    /// All passes that ran, including the canonical pass itself.
    pub passes: Vec<ReplayCheckPass>,
    /// Names of passes whose digest diverged from canonical.
    pub mismatched: Vec<String>,
}

/// Compute the canonical, order-independent digest of replay-relevant state.
pub fn state_summary(db: &Db) -> Result<StateSummary, String> {
    let mut areas = Vec::new();
    for summary in replay_summary_table_hashes(db)? {
        areas.push(AreaSummary {
            area: summary.table,
            hash: summary.hash,
            count: summary.count,
        });
    }
    areas.sort_by(|left, right| left.area.cmp(&right.area));

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:replay-state-summary:v1");
    for area in &areas {
        hasher.update(&(area.area.len() as u64).to_le_bytes());
        hasher.update(area.area.as_bytes());
        hasher.update(&(area.count as u64).to_le_bytes());
        hasher.update(&area.hash);
    }
    Ok(StateSummary {
        state_hash: *hasher.finalize().as_bytes(),
        areas,
    })
}

/// Compare each replay pass summary against the canonical pass.
///
/// `passes` is `(name, summary)` for every pass, with the canonical pass first.
/// The report records per-area diffs for any pass whose digest diverges, which
/// localizes a determinism bug to a specific table.
pub fn compare_replay_passes(passes: Vec<(String, StateSummary)>) -> ReplayCheckReport {
    let canonical = passes
        .first()
        .map(|(_, summary)| summary.clone())
        .expect("replay-check runs at least the canonical pass");
    let mut report = ReplayCheckReport {
        canonical_hash: canonical.state_hash,
        passes: Vec::new(),
        mismatched: Vec::new(),
    };
    for (name, summary) in passes {
        let area_diffs = if summary.state_hash == canonical.state_hash {
            Vec::new()
        } else {
            report.mismatched.push(name.clone());
            area_diffs(&canonical, &summary)
        };
        report.passes.push(ReplayCheckPass {
            name,
            state_hash: summary.state_hash,
            area_diffs,
        });
    }
    report
}

/// Hash every schema-declared replay-summary table.
pub fn replay_summary_table_hashes(db: &Db) -> Result<Vec<TableSummary>, String> {
    let mut summaries = Vec::with_capacity(db.replay_summary_tables().len());
    for table in db.replay_summary_tables() {
        summaries.push(hash_table(db, *table)?);
    }
    Ok(summaries)
}

/// Report which state areas differ between two summaries, with their counts.
fn area_diffs(left: &StateSummary, right: &StateSummary) -> Vec<String> {
    let mut names: Vec<&str> = left
        .areas
        .iter()
        .map(|area| area.area.as_str())
        .chain(right.areas.iter().map(|area| area.area.as_str()))
        .collect();
    names.sort_unstable();
    names.dedup();

    let mut diffs = Vec::new();
    for name in names {
        let left_area = left.areas.iter().find(|area| area.area == name);
        let right_area = right.areas.iter().find(|area| area.area == name);
        let differs = match (left_area, right_area) {
            (Some(l), Some(r)) => l.hash != r.hash || l.count != r.count,
            _ => true,
        };
        if differs {
            let left_count = left_area.map(|area| area.count).unwrap_or(0);
            let right_count = right_area.map(|area| area.count).unwrap_or(0);
            diffs.push(format!("{name}: canonical={left_count} pass={right_count}"));
        }
    }
    diffs
}

/// Hash one table's rows canonically, independent of insertion order.
///
/// Rows are ordered by every column so the digest depends only on content, and
/// each cell is serialized with a type tag so distinct SQLite types never
/// alias.
fn hash_table(db: &Db, table: TableName) -> Result<TableSummary, String> {
    let quoted = quoted_table_name(table).map_err(|err| err.to_string())?;
    let columns = table_columns(db, &quoted)?;
    if columns.is_empty() {
        return Err(format!("table {} has no columns to hash", table.as_str()));
    }
    let column_list = quoted_identifier_list(&columns).map_err(|err| err.to_string())?;

    let mut stmt = db
        .conn()
        .prepare(&format!(
            "SELECT {column_list} FROM {quoted} ORDER BY {column_list}"
        ))
        .map_err(|err| format!("prepare hash scan for {}: {err}", table.as_str()))?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:store-table-summary:v1");
    hasher.update(&(table.as_str().len() as u64).to_le_bytes());
    hasher.update(table.as_str().as_bytes());
    for column in &columns {
        hasher.update(&(column.len() as u64).to_le_bytes());
        hasher.update(column.as_bytes());
    }

    let column_count = columns.len();
    let mut count = 0usize;
    let mut rows = stmt
        .query([])
        .map_err(|err| format!("scan {}: {err}", table.as_str()))?;
    while let Some(row) = rows
        .next()
        .map_err(|err| format!("scan {}: {err}", table.as_str()))?
    {
        for index in 0..column_count {
            let value = row
                .get_ref(index)
                .map_err(|err| format!("read {} cell: {err}", table.as_str()))?;
            hash_cell(&mut hasher, value);
        }
        count += 1;
    }
    Ok(TableSummary {
        table: table.as_str().to_string(),
        hash: *hasher.finalize().as_bytes(),
        count,
    })
}

fn table_columns(db: &Db, quoted_table: &str) -> Result<Vec<String>, String> {
    let mut stmt = db
        .conn()
        .prepare(&format!("PRAGMA table_info({quoted_table})"))
        .map_err(|err| format!("read columns: {err}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|err| format!("read columns: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("read columns: {err}"))
}

fn hash_cell(hasher: &mut blake3::Hasher, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => hasher.update(&[0u8]),
        ValueRef::Integer(int) => {
            hasher.update(&[1u8]);
            hasher.update(&int.to_le_bytes())
        }
        ValueRef::Real(real) => {
            hasher.update(&[2u8]);
            hasher.update(&real.to_bits().to_le_bytes())
        }
        ValueRef::Text(text) => {
            hasher.update(&[3u8]);
            hasher.update(&(text.len() as u64).to_le_bytes());
            hasher.update(text)
        }
        ValueRef::Blob(blob) => {
            hasher.update(&[4u8]);
            hasher.update(&(blob.len() as u64).to_le_bytes());
            hasher.update(blob)
        }
    };
}
