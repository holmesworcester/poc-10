//! Commands for generating content events.
//!
//! Generation is deterministic from `(start_timestamp, count, size)`, which
//! lets CLI tests compare counts and throughput without relying on random test
//! fixtures. The command proposes shared events only; storing and projection are
//! handled by the common worker.

use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::ContentEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateReport {
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

pub trait GenerateRead {
    fn max_timestamp(&self) -> Result<u64, String>;
}

pub fn generate_next(
    context: &impl GenerateRead,
    num_events: usize,
    event_size: usize,
) -> Result<CommandOutput<GenerateReport>, String> {
    let start_timestamp = context.max_timestamp()?.saturating_add(1);
    generate(start_timestamp, num_events, event_size)
}

pub fn generate(
    start_timestamp: u64,
    num_events: usize,
    event_size: usize,
) -> Result<CommandOutput<GenerateReport>, String> {
    let mut records = Vec::with_capacity(num_events);

    for offset in 0..num_events {
        let timestamp = start_timestamp + offset as u64;
        let payload = payload(timestamp, event_size);
        let bytes = codec::encode(&ContentEvent { timestamp, payload });
        let record = codec::record_from_bytes(bytes)?;
        records.push(record);
    }

    Ok(CommandOutput::with_events(
        GenerateReport {
            first_timestamp: start_timestamp,
            last_timestamp: start_timestamp + num_events as u64 - 1,
        },
        records,
    ))
}

fn payload(timestamp: u64, size: usize) -> Vec<u8> {
    // Derive pseudo-random-looking bytes from the timestamp so large payload
    // tests move nontrivial data while remaining reproducible.
    let mut seed = blake3::Hasher::new();
    seed.update(b"content-payload:");
    seed.update(&timestamp.to_be_bytes());
    let mut state = *seed.finalize().as_bytes();
    let mut out = Vec::with_capacity(size);

    while out.len() < size {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&state);
        state = *hasher.finalize().as_bytes();
        let remaining = size - out.len();
        out.extend_from_slice(&state[..remaining.min(state.len())]);
    }

    out
}
