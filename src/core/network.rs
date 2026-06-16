//! Core-owned opaque network IO boundary and TCP frame pump.
//!
//! Protocol code hands opaque frame bytes to this module. Core stores outbound
//! bytes in per-target memory-local SQLite queue rows, keeps a separate active
//! target index for fair scheduling, pumps queued frames to TCP when a daemon
//! tick has socket capacity, and delivers inbound TCP frames to a
//! caller-provided intake callback as soon as the frame has been decoded.
//!
//! The queue rows are process-local operational state, not protocol truth.
//! Durable work lives in projected facts, context, rows, and intents; network
//! bytes are retried by keeping queued rows until the TCP pump deletes them
//! after a successful write.
//!
//! The outbound queue key is intentionally deterministic: the same route and
//! same bytes map to the same row. That gives the boundary a cheap idempotence
//! property while callers are still free to retry after crashes. If this module starts
//! parsing payloads, naming protocol concepts, or deciding when a row should be
//! produced, it has crossed out of core and into a fact module.
//!
//! Outbound rows are produced by protocol intent handlers and consumed by the
//! TCP pump. Inbound frames are read by the TCP pump and handed directly to the
//! daemon's protocol intake callback. This keeps socket readiness, backpressure,
//! and partial writes out of protocol handlers while also keeping protocol
//! admission out of this network module.
//!
//! Change this file for frame network mechanics: listener setup,
//! length-prefix framing, queue idempotence, local row cleanup, or bounded IO.
//! Change connection-frame protocol helpers or connection network intents when
//! the bytes inside a frame need new protocol meaning.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;
use std::time::{Duration, Instant};

use crate::core::store::{ReplayTables, SchemaSource, Store, TableName, TableRow};

/// Ephemeral outbound network frame queue table.
pub const OUTBOUND_TABLE: TableName = TableName::new("network_out");
/// Ephemeral active-target index for the outbound network queue.
pub const OUTBOUND_TARGETS_TABLE: TableName = TableName::new("network_out_targets");
const MAX_FRAME_BYTES: usize = 128 * 1024 * 1024;
const WRITE_FRAME_BUDGET: Duration = Duration::from_secs(1);

/// Store declaration for the core-owned outbound byte queue.
///
/// Network rows are core IO state, so their schema source lives next to this
/// queue code and the concrete runtime includes it like any other declaration.
/// The rows are memory-only so a restart never turns stale socket staging into
/// protocol-visible work.
pub const SCHEMA_SOURCE: SchemaSource = SchemaSource {
    ddl: r#"
CREATE TEMP TABLE IF NOT EXISTS network_out (
    row_key BLOB PRIMARY KEY NOT NULL,
    row_value BLOB NOT NULL
);
CREATE TEMP TABLE IF NOT EXISTS network_out_targets (
    row_key BLOB PRIMARY KEY NOT NULL,
    row_value BLOB NOT NULL
);
"#,
    row_tables: &[OUTBOUND_TABLE, OUTBOUND_TARGETS_TABLE],
    row_schemas: &[],
    replay: ReplayTables {
        protected: &[],
        reset: &[OUTBOUND_TABLE, OUTBOUND_TARGETS_TABLE],
        summary: &[],
    },
};

/// Destination for opaque outbound frame bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkTarget {
    addr: SocketAddr,
}

impl NetworkTarget {
    /// Build a target from a socket address.
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// Return the socket address this target names.
    pub fn addr(self) -> SocketAddr {
        self.addr
    }
}

/// Address observed for an inbound frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkSource {
    addr: SocketAddr,
}

impl NetworkSource {
    /// Build a source from a socket address.
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// Return the socket address this source names.
    pub fn addr(self) -> SocketAddr {
        self.addr
    }
}

/// Opaque protocol frame ready to write to a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundFrame {
    pub bytes: Vec<u8>,
}

/// Memory-queued outbound frame.
///
/// The key is deterministic from direction, target, and frame bytes. The value
/// is the exact frame bytes that will be length-prefixed on the TCP stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundNetworkRow {
    pub key: Vec<u8>,
    pub target: NetworkTarget,
    pub bytes: Vec<u8>,
}

impl OutboundNetworkRow {
    /// Build a deterministic outbound queue row.
    pub fn new(target: NetworkTarget, bytes: Vec<u8>) -> Self {
        Self {
            key: queue_key(b"outbound", target.addr(), &bytes),
            target,
            bytes,
        }
    }
}

/// Queue one outbound frame for the daemon TCP pump.
pub fn send(store: &Store, target: NetworkTarget, frame: OutboundFrame) -> Result<(), String> {
    let OutboundFrame { bytes } = frame;
    let row = OutboundNetworkRow::new(target, bytes);
    enqueue_outbound(store, std::slice::from_ref(&row)).map(|_| ())
}

/// Insert outbound rows idempotently.
///
/// Frame rows and their active-target index rows become visible in one store
/// transaction. The returned count is the number of new frame rows, not target
/// index rows. Deletion is a separate, explicit step so callers can commit
/// their own "sent" bookkeeping at the right boundary.
pub fn enqueue_outbound(store: &Store, rows: &[OutboundNetworkRow]) -> Result<usize, String> {
    store
        .write_transaction(|tx| {
            let inserted_frames =
                tx.insert_table_rows_in_tx(rows.iter().map(outbound_table_row).collect())?;
            tx.insert_table_rows_in_tx(outbound_target_table_rows(rows))?;
            Ok(inserted_frames)
        })
        .map_err(|err| format!("enqueue outbound network rows: {err}"))
}

/// Claim at most `limit` outbound rows for one concrete target.
///
/// The target prefix in the row key is the performance property that matters:
/// a slow route does not require a full-table scan and does not block other
/// routes from being claimed by their own callers.
pub fn claim_outbound_for_target(
    store: &Store,
    target: NetworkTarget,
    limit: usize,
) -> Result<Vec<OutboundNetworkRow>, String> {
    store
        .table_rows_with_key_prefix(OUTBOUND_TABLE, &target_prefix(target.addr()), limit)
        .map_err(|err| format!("claim outbound network rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_outbound(key, &value))
        .collect()
}

/// Discover targets with queued outbound rows.
///
/// Core keeps this as a separate target index so a blocked peer with many
/// queued frames does not make the scheduler scan frame rows to find the next
/// address.
pub fn queued_outbound_targets(store: &Store, limit: usize) -> Result<Vec<NetworkTarget>, String> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    store
        .table_rows_with_key_prefix(OUTBOUND_TARGETS_TABLE, &[], limit)
        .map_err(|err| format!("discover outbound network targets: {err}"))?
        .into_iter()
        .map(|(key, _)| decode_target_key(&key).map(NetworkTarget::new))
        .collect()
}

/// Counts observed while draining the queued outbound network rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundPumpReport {
    /// Distinct queued targets considered in this pass.
    pub target_count: usize,
    /// Frames successfully written and removed from the queue.
    pub sent_frames: usize,
    /// Targets that still have queued rows after a TCP connect or write failed.
    pub deferred_targets: usize,
}

/// Drain queued outbound frames to TCP targets.
///
/// This is the daemon-side outbound pump. It discovers address-keyed queued
/// rows, opens a bounded TCP stream per target, and deletes each row only after
/// its length-prefixed frame has been written. TCP failures are backpressure or
/// reachability signals: they defer that target for a later pass instead of
/// turning opaque transport state into durable protocol truth.
pub fn pump_outbound(
    store: &Store,
    max_targets: usize,
    max_frames_per_target: usize,
) -> Result<OutboundPumpReport, String> {
    let targets = queued_outbound_targets(store, max_targets)?;
    let mut report = OutboundPumpReport {
        target_count: targets.len(),
        ..OutboundPumpReport::default()
    };
    if max_frames_per_target == 0 {
        return Ok(report);
    }
    for target in targets {
        match pump_outbound_target(store, target, max_frames_per_target)? {
            TargetPumpOutcome::Drained { sent_frames } => {
                report.sent_frames += sent_frames;
            }
            TargetPumpOutcome::Deferred { sent_frames } => {
                report.sent_frames += sent_frames;
                report.deferred_targets += 1;
            }
        }
    }
    Ok(report)
}

/// Claim specific outbound rows by exact deterministic key.
///
/// This lets tests and synchronous send helpers prove the deterministic rows
/// they just staged are present before attempting a socket write.
pub fn claim_exact_outbound(
    store: &Store,
    rows: &[OutboundNetworkRow],
) -> Result<Vec<OutboundNetworkRow>, String> {
    let mut claimed = Vec::with_capacity(rows.len());
    for expected in rows {
        let value = store
            .table_row(OUTBOUND_TABLE, &expected.key)
            .map_err(|err| format!("claim exact outbound network row: {err}"))?
            .ok_or_else(|| "queued outbound network row was not claimable".to_string())?;
        let row = decode_outbound(expected.key.clone(), &value)?;
        if row.target != expected.target || row.bytes != expected.bytes {
            return Err("queued outbound network row did not match expected bytes".to_string());
        }
        claimed.push(row);
    }
    Ok(claimed)
}

/// Remove outbound rows that have been successfully handed off by the caller.
pub fn delete_outbound(store: &Store, rows: &[OutboundNetworkRow]) -> Result<(), String> {
    store
        .write_transaction(|tx| {
            tx.delete_table_rows_in_tx(
                OUTBOUND_TABLE,
                rows.iter().map(|row| row.key.clone()).collect(),
            )?;
            prune_outbound_targets_in_tx(tx, rows)?;
            Ok(())
        })
        .map(|_| ())
        .map_err(|err| format!("delete outbound network rows: {err}"))
}

fn outbound_table_row(row: &OutboundNetworkRow) -> TableRow {
    TableRow {
        table: OUTBOUND_TABLE,
        key: row.key.clone(),
        value: row.bytes.clone(),
    }
}

fn outbound_target_table_rows(rows: &[OutboundNetworkRow]) -> Vec<TableRow> {
    let mut targets = Vec::new();
    for row in rows {
        if targets.contains(&row.target) {
            continue;
        }
        targets.push(row.target);
    }
    targets.into_iter().map(outbound_target_table_row).collect()
}

fn outbound_target_table_row(target: NetworkTarget) -> TableRow {
    TableRow {
        table: OUTBOUND_TARGETS_TABLE,
        key: target_prefix(target.addr()),
        value: Vec::new(),
    }
}

fn prune_outbound_targets_in_tx(
    store: &Store,
    rows: &[OutboundNetworkRow],
) -> rusqlite::Result<()> {
    let mut targets = Vec::new();
    for row in rows {
        if targets.contains(&row.target) {
            continue;
        }
        targets.push(row.target);
    }
    for target in targets {
        if store
            .table_rows_with_key_prefix(OUTBOUND_TABLE, &target_prefix(target.addr()), 1)?
            .is_empty()
        {
            store.delete_table_rows_in_tx(
                OUTBOUND_TARGETS_TABLE,
                vec![target_prefix(target.addr())],
            )?;
        }
    }
    Ok(())
}

fn decode_outbound(key: Vec<u8>, value: &[u8]) -> Result<OutboundNetworkRow, String> {
    let addr = decode_addr_from_key(&key)?;
    Ok(OutboundNetworkRow {
        key,
        target: NetworkTarget::new(addr),
        bytes: value.to_vec(),
    })
}

fn target_prefix(addr: SocketAddr) -> Vec<u8> {
    let addr = addr.to_string();
    let addr = addr.as_bytes();
    let mut out = Vec::with_capacity(4 + addr.len());
    out.extend_from_slice(&(addr.len() as u32).to_be_bytes());
    out.extend_from_slice(addr);
    out
}

fn decode_addr_from_key(key: &[u8]) -> Result<SocketAddr, String> {
    let (addr, addr_end) = decode_addr_prefix(key)?;
    if key.len() != addr_end + 32 {
        return Err("network row key has invalid length".to_string());
    }
    Ok(addr)
}

fn decode_target_key(key: &[u8]) -> Result<SocketAddr, String> {
    let (addr, addr_end) = decode_addr_prefix(key)?;
    if key.len() != addr_end {
        return Err("network target key has invalid length".to_string());
    }
    Ok(addr)
}

fn decode_addr_prefix(key: &[u8]) -> Result<(SocketAddr, usize), String> {
    let mut offset = 0;
    let addr_len = read_u32(key, &mut offset)? as usize;
    let addr_end = offset
        .checked_add(addr_len)
        .ok_or_else(|| "network row address length overflow".to_string())?;
    let addr_bytes = key
        .get(offset..addr_end)
        .ok_or_else(|| "network row address is truncated".to_string())?;
    let addr = std::str::from_utf8(addr_bytes)
        .map_err(|_| "network row address is not utf8".to_string())
        .and_then(|addr| {
            SocketAddr::from_str(addr).map_err(|_| "network row address is invalid".to_string())
        })?;
    Ok((addr, addr_end))
}

fn read_u32(value: &[u8], offset: &mut usize) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "network row length overflow".to_string())?;
    let bytes: [u8; 4] = value
        .get(*offset..end)
        .ok_or_else(|| "network row length is truncated".to_string())?
        .try_into()
        .expect("slice length checked");
    *offset = end;
    Ok(u32::from_be_bytes(bytes))
}

fn queue_key(kind: &[u8], addr: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    // Include direction, route, length, and bytes in the digest. The route is
    // also present as a plain prefix for efficient claims; the digest makes the
    // rest of the key compact and stable.
    let mut key = target_prefix(addr);
    let mut hasher = blake3::Hasher::new();
    hasher.update(kind);
    hasher.update(addr.to_string().as_bytes());
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    key.extend_from_slice(hasher.finalize().as_bytes());
    key
}

/// Counts observed while pumping one TCP stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamReport {
    /// Frames written to a stream.
    pub sent_frames: usize,
    /// Non-empty frames read from a stream and delivered to the intake callback.
    pub received_frames: usize,
}

/// Result of polling a reusable listener once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptReport<T> {
    /// Number of streams accepted during this poll.
    pub accepted_connections: usize,
    /// Caller-selected report value for accepted streams.
    pub value: T,
}

/// Bound TCP listener that can be polled by a caller-owned loop.
pub struct Listener {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl Listener {
    /// Return the address actually bound by the listener.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accept and pump available inbound streams up to `max_streams`.
    ///
    /// If no stream is ready, the returned report has zero accepted
    /// connections. This gives higher-level schedulers a nonblocking accept
    /// step without moving any byte interpretation into core. The callback is
    /// called once per non-empty decoded frame, before the next frame is read.
    /// Draining more than one stream matters because higher layers may
    /// intentionally send many short streams as independent idempotent work
    /// items.
    pub fn accept_available(
        &self,
        max_streams: usize,
        mut on_frame: impl FnMut(NetworkSource, Vec<u8>) -> Result<(), String>,
    ) -> Result<AcceptReport<StreamReport>, String> {
        let mut accepted_connections = 0;
        let mut value = StreamReport::default();
        for _ in 0..max_streams {
            let (mut stream, source_addr) = match self.listener.accept() {
                Ok(accepted) => accepted,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(format!("accept tcp stream: {err}")),
            };
            stream
                .set_nonblocking(false)
                .map_err(|err| format!("set stream blocking: {err}"))?;
            stream
                .set_nodelay(true)
                .map_err(|err| format!("set stream nodelay: {err}"))?;
            let report =
                read_inbound_frames(&mut stream, NetworkSource::new(source_addr), &mut on_frame)?;
            accepted_connections += 1;
            value.sent_frames += report.sent_frames;
            value.received_frames += report.received_frames;
        }
        Ok(AcceptReport {
            accepted_connections,
            value,
        })
    }
}

/// Bind a reusable TCP listener for caller-owned scheduling loops.
pub fn listen(listen: SocketAddr) -> Result<Listener, String> {
    let listener = TcpListener::bind(listen).map_err(|err| format!("listen: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("set listener nonblocking: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("listener local addr: {err}"))?;
    Ok(Listener {
        listener,
        local_addr,
    })
}

/// Open a TCP stream, send outbound rows for that target, and return.
///
/// This synchronous helper stages bytes in the core outbound queue and calls
/// `on_sent` only after bounded socket writes and queue deletion complete. The
/// daemon normally uses `pump_outbound` so already queued rows can be drained
/// by target address.
pub fn send_once<T>(
    store: &Store,
    target: NetworkTarget,
    rows: Vec<OutboundNetworkRow>,
    mut value: T,
    mut on_sent: impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
) -> Result<T, String> {
    let mut stream = connect(target.addr()).map_err(|err| format!("open tcp stream: {err}"))?;
    let mut report = StreamReport::default();
    write_outbound(
        store,
        &mut stream,
        target,
        rows,
        &mut value,
        &mut on_sent,
        &mut report,
    )?;
    stream
        .shutdown(Shutdown::Both)
        .map_err(|err| format!("shutdown sent stream: {err}"))?;
    Ok(value)
}

fn read_inbound_frames(
    stream: &mut TcpStream,
    source: NetworkSource,
    on_frame: &mut impl FnMut(NetworkSource, Vec<u8>) -> Result<(), String>,
) -> Result<StreamReport, String> {
    let mut report = StreamReport::default();
    loop {
        let bytes = match read_frame(stream) {
            Ok(bytes) => bytes,
            Err(err) if is_stream_closed(&err) => break,
            Err(err) => return Err(format!("read frame: {err}")),
        };
        if bytes.is_empty() {
            continue;
        }
        on_frame(source, bytes)?;
        report.received_frames += 1;
    }

    Ok(report)
}

fn write_outbound<T>(
    store: &Store,
    stream: &mut TcpStream,
    target: NetworkTarget,
    rows: Vec<OutboundNetworkRow>,
    value: &mut T,
    on_sent: &mut impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
    report: &mut StreamReport,
) -> Result<(), String> {
    if rows.is_empty() {
        return Ok(());
    }
    ensure_target(target, &rows)?;
    enqueue_outbound(store, &rows)?;
    let claimed = claim_exact_outbound(store, &rows)?;
    write_claimed_outbound(store, stream, target, claimed, value, on_sent, report)
}

fn write_claimed_outbound<T>(
    store: &Store,
    stream: &mut TcpStream,
    target: NetworkTarget,
    claimed: Vec<OutboundNetworkRow>,
    value: &mut T,
    on_sent: &mut impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
    report: &mut StreamReport,
) -> Result<(), String> {
    ensure_target(target, &claimed)?;
    for row in &claimed {
        write_frame(stream, &row.bytes).map_err(|err| format!("write frame: {err}"))?;
    }
    delete_outbound(store, &claimed)?;
    on_sent(&claimed, value)?;
    report.sent_frames += claimed.len();
    Ok(())
}

enum TargetPumpOutcome {
    Drained { sent_frames: usize },
    Deferred { sent_frames: usize },
}

fn pump_outbound_target(
    store: &Store,
    target: NetworkTarget,
    limit: usize,
) -> Result<TargetPumpOutcome, String> {
    let rows = claim_outbound_for_target(store, target, limit)?;
    if rows.is_empty() {
        delete_outbound_target_if_empty(store, target)?;
        return Ok(TargetPumpOutcome::Drained { sent_frames: 0 });
    }
    let mut stream = match connect(target.addr()) {
        Ok(stream) => stream,
        Err(_) => return Ok(TargetPumpOutcome::Deferred { sent_frames: 0 }),
    };
    let mut sent_frames = 0;
    for row in rows {
        ensure_target(target, std::slice::from_ref(&row))?;
        if write_frame(&mut stream, &row.bytes).is_err() {
            return Ok(TargetPumpOutcome::Deferred { sent_frames });
        }
        delete_outbound(store, std::slice::from_ref(&row))?;
        sent_frames += 1;
    }
    let _ = stream.shutdown(Shutdown::Both);
    Ok(TargetPumpOutcome::Drained { sent_frames })
}

fn delete_outbound_target_if_empty(store: &Store, target: NetworkTarget) -> Result<(), String> {
    store
        .write_transaction(|tx| {
            if tx
                .table_rows_with_key_prefix(OUTBOUND_TABLE, &target_prefix(target.addr()), 1)?
                .is_empty()
            {
                tx.delete_table_rows_in_tx(
                    OUTBOUND_TARGETS_TABLE,
                    vec![target_prefix(target.addr())],
                )?;
            }
            Ok(())
        })
        .map_err(|err| format!("delete empty outbound target: {err}"))
}

fn ensure_target(target: NetworkTarget, rows: &[OutboundNetworkRow]) -> Result<(), String> {
    if rows.iter().all(|row| row.target == target) {
        return Ok(());
    }
    Err("outbound network row target does not match stream target".to_string())
}

fn connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    write_frame_with_budget(stream, bytes, WRITE_FRAME_BUDGET)
}

fn write_frame_with_budget(
    stream: &mut TcpStream,
    bytes: &[u8],
    budget: Duration,
) -> std::io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"))?;
    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + budget;
    let result = (|| {
        write_all_until(stream, &len.to_be_bytes(), deadline)?;
        write_all_until(stream, bytes, deadline)?;
        stream.flush()
    })();
    let reset = stream.set_nonblocking(false);
    match (result, reset) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err),
    }
}

fn write_all_until(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "tcp frame write budget exhausted",
            ));
        }
        match stream.write(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "tcp stream accepted zero bytes",
                ));
            }
            Ok(n) => bytes = &bytes[n..],
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn is_stream_closed(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn write_frame_sends_length_prefixed_bytes_within_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let reader = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut len = [0; 4];
            stream.read_exact(&mut len).expect("read len");
            let mut body = vec![0; u32::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).expect("read body");
            body
        });

        let mut stream = TcpStream::connect(addr).expect("connect");
        write_frame_with_budget(&mut stream, b"abc", Duration::from_secs(1)).expect("write frame");

        assert_eq!(reader.join().expect("reader thread"), b"abc");
    }

    #[test]
    fn write_frame_zero_budget_times_out_before_blocking() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let reader = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept");
            thread::sleep(Duration::from_millis(20));
        });

        let mut stream = TcpStream::connect(addr).expect("connect");
        let err = write_frame_with_budget(&mut stream, b"abc", Duration::ZERO)
            .expect_err("zero budget should time out");

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        reader.join().expect("reader thread");
    }

    #[test]
    fn accept_available_drains_ready_streams_up_to_limit() {
        let listener = listen("127.0.0.1:0".parse().expect("listen addr")).expect("listen");
        let addr = listener.local_addr();
        let writers = (0..3)
            .map(|idx| {
                thread::spawn(move || {
                    let mut stream = TcpStream::connect(addr).expect("connect");
                    let body = vec![idx as u8; idx + 1];
                    write_frame_with_budget(&mut stream, &body, Duration::from_secs(1))
                        .expect("write frame");
                    stream.shutdown(Shutdown::Write).expect("shutdown write");
                })
            })
            .collect::<Vec<_>>();
        thread::sleep(Duration::from_millis(50));

        let mut frames = Vec::new();
        let first = listener
            .accept_available(2, |source, bytes| {
                frames.push((source.addr(), bytes));
                Ok(())
            })
            .expect("accept first batch");
        let second = listener
            .accept_available(2, |source, bytes| {
                frames.push((source.addr(), bytes));
                Ok(())
            })
            .expect("accept second batch");
        for writer in writers {
            writer.join().expect("writer thread");
        }

        assert_eq!(first.accepted_connections, 2);
        assert_eq!(first.value.received_frames, 2);
        assert_eq!(second.accepted_connections, 1);
        assert_eq!(second.value.received_frames, 1);
        frames.sort_by(|left, right| left.1.cmp(&right.1));
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].1, vec![0]);
        assert_eq!(frames[1].1, vec![1, 1]);
        assert_eq!(frames[2].1, vec![2, 2, 2]);
    }

    #[test]
    fn empty_frame_is_tcp_heartbeat_not_protocol_input() {
        let listener = listen("127.0.0.1:0".parse().expect("listen addr")).expect("listen");
        let addr = listener.local_addr();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            write_frame_with_budget(&mut stream, b"", Duration::from_secs(1))
                .expect("write heartbeat");
            stream.shutdown(Shutdown::Write).expect("shutdown write");
        });
        thread::sleep(Duration::from_millis(50));

        let mut frames = Vec::new();
        let report = listener
            .accept_available(1, |source, bytes| {
                frames.push((source.addr(), bytes));
                Ok(())
            })
            .expect("accept heartbeat");
        writer.join().expect("writer thread");

        assert_eq!(report.accepted_connections, 1);
        assert_eq!(report.value.received_frames, 0);
        assert!(frames.is_empty());
    }
}
