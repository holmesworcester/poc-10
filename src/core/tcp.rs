//! Blocking TCP frame pump over opaque network queue rows.
//!
//! This file is deliberately a byte mover. It opens sockets, reads and writes
//! `[u32 length][bytes]` frames, records inbound bytes in the core queue, and
//! drains outbound bytes for the connected route.
//!
//! The protocol boundary is the stored queue rows in `core/network_queues.rs`.
//! On receive, TCP wraps a frame in an `InboundNetworkRow` keyed by the observed
//! `NetworkSource`, inserts it into the inbound queue, hands that exact row to
//! the caller, and deletes it only after the caller returns protocol-produced
//! outbound rows. On send, callers provide `OutboundNetworkRow`s keyed by one
//! `NetworkTarget`; TCP inserts them into the outbound queue, claims rows for
//! that same target, writes their opaque bytes as frames, deletes the sent core
//! rows, and then reports the sent rows back through `on_sent` so protocol-owned
//! bookkeeping can advance. Core never interprets or constructs protocol bytes.
//!
//! The invariant is routing correctness: each outbound row is sent only on the
//! stream for its `NetworkTarget`, and each inbound row is recorded with the
//! `NetworkSource` observed from the socket before any worker sees the bytes. A
//! frame is first written to a core queue row, then handed to the caller, and
//! only deleted after the caller accepts responsibility for it. The same shape
//! is used on send: callers provide opaque rows, this pump writes frames, and
//! then calls back so the caller can update its own send bookkeeping. Keep this
//! file boring; cleverness here usually means a domain worker is missing.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::core::network_queues::{
    self, InboundNetworkRow, NetworkSource, NetworkTarget, OutboundNetworkRow,
};
use crate::core::store::Store;

const MAX_FRAME_BYTES: usize = 128 * 1024 * 1024;

/// Counts observed while pumping one TCP stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamReport {
    pub sent_frames: usize,
    pub received_frames: usize,
}

/// Result of accepting one or more TCP streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeReport<T> {
    pub local_addr: SocketAddr,
    pub accepted_connections: usize,
    pub value: T,
}

/// Result of polling a reusable listener once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptReport<T> {
    pub accepted_connections: usize,
    pub value: T,
}

/// Bound TCP listener that can be polled by a caller-owned loop.
pub struct Listener {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl Listener {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accept and pump at most one available stream.
    ///
    /// If no stream is ready, the supplied value is returned unchanged. This
    /// gives higher-level schedulers a nonblocking accept step without moving
    /// any byte interpretation into core.
    pub fn accept_available<T>(
        &self,
        store: &Store,
        value: T,
        on_inbound: impl FnMut(InboundNetworkRow, &mut T) -> Result<Vec<OutboundNetworkRow>, String>,
        on_sent: impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
    ) -> Result<AcceptReport<T>, String> {
        let (mut stream, source_addr) = match self.listener.accept() {
            Ok(accepted) => accepted,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(AcceptReport {
                    accepted_connections: 0,
                    value,
                })
            }
            Err(err) => return Err(format!("accept tcp stream: {err}")),
        };
        stream
            .set_nonblocking(false)
            .map_err(|err| format!("set stream blocking: {err}"))?;
        stream
            .set_nodelay(true)
            .map_err(|err| format!("set stream nodelay: {err}"))?;
        let target = NetworkTarget::new(source_addr);
        let (_, value) = pump_stream(
            store,
            &mut stream,
            target,
            Vec::new(),
            value,
            on_inbound,
            on_sent,
        )?;
        Ok(AcceptReport {
            accepted_connections: 1,
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

/// Open a TCP stream, send initial rows, then react to inbound frames.
///
/// `on_inbound` is the protocol boundary: it receives an opaque inbound row and
/// may return more opaque outbound rows for the same route. `on_sent` is called
/// after frame writes and queue deletion, so protocol bookkeeping can lag socket
/// writes without being hidden in core.
pub fn connect_exchange<T>(
    store: &Store,
    target: NetworkTarget,
    initial_outbound: Vec<OutboundNetworkRow>,
    value: T,
    on_inbound: impl FnMut(InboundNetworkRow, &mut T) -> Result<Vec<OutboundNetworkRow>, String>,
    on_sent: impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
) -> Result<T, String> {
    let mut stream = connect(target.addr()).map_err(|err| format!("open tcp stream: {err}"))?;
    pump_stream(
        store,
        &mut stream,
        target,
        initial_outbound,
        value,
        on_inbound,
        on_sent,
    )
    .map(|(_, value)| value)
}

/// Serve a fixed number of incoming streams.
///
/// This POC runner is intentionally finite; tests can ask it to accept exactly
/// the number of streams they intend to drive. A long-lived scheduler can wrap
/// this same stream pump later without changing the byte/queue boundary.
pub fn serve<T>(
    store: &Store,
    listen: SocketAddr,
    accept_count: usize,
    mut value: T,
    mut on_inbound: impl FnMut(InboundNetworkRow, &mut T) -> Result<Vec<OutboundNetworkRow>, String>,
    mut on_sent: impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
) -> Result<ServeReport<T>, String> {
    let listener = TcpListener::bind(listen).map_err(|err| format!("listen: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("listener local addr: {err}"))?;

    let mut accepted_connections = 0;
    for _ in 0..accept_count {
        let (mut stream, source_addr) = listener
            .accept()
            .map_err(|err| format!("accept tcp stream: {err}"))?;
        stream
            .set_nodelay(true)
            .map_err(|err| format!("set stream nodelay: {err}"))?;
        let target = NetworkTarget::new(source_addr);
        let (_, next_value) = pump_stream(
            store,
            &mut stream,
            target,
            Vec::new(),
            value,
            &mut on_inbound,
            &mut on_sent,
        )?;
        value = next_value;
        accepted_connections += 1;
    }

    Ok(ServeReport {
        local_addr,
        accepted_connections,
        value,
    })
}

// Drive one stream until the remote side closes it or neither side has more
// bytes to write. Every frame passes through the inbound queue before the
// callback sees it, which keeps the core/protocol handoff visible in tests.
fn pump_stream<T>(
    store: &Store,
    stream: &mut TcpStream,
    target: NetworkTarget,
    initial_outbound: Vec<OutboundNetworkRow>,
    mut value: T,
    mut on_inbound: impl FnMut(InboundNetworkRow, &mut T) -> Result<Vec<OutboundNetworkRow>, String>,
    mut on_sent: impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
) -> Result<(StreamReport, T), String> {
    let mut report = StreamReport::default();
    let mut write_open = true;
    write_outbound(
        store,
        stream,
        target,
        initial_outbound,
        &mut value,
        &mut on_sent,
        &mut report,
    )?;

    loop {
        let bytes = match read_frame(stream) {
            Ok(bytes) => bytes,
            Err(err) if is_stream_closed(&err) => break,
            Err(err) => return Err(format!("read frame: {err}")),
        };
        report.received_frames += 1;

        let inbound = InboundNetworkRow::new(NetworkSource::new(target.addr()), bytes);
        network_queues::enqueue_inbound(store, std::slice::from_ref(&inbound))?;
        let outbound = on_inbound(inbound.clone(), &mut value)?;
        network_queues::delete_inbound(store, std::slice::from_ref(&inbound))?;

        if outbound.is_empty() {
            if write_open {
                stream
                    .shutdown(Shutdown::Write)
                    .map_err(|err| format!("shutdown stream write: {err}"))?;
                write_open = false;
            }
        } else {
            write_outbound(
                store,
                stream,
                target,
                outbound,
                &mut value,
                &mut on_sent,
                &mut report,
            )?;
        }
    }

    Ok((report, value))
}

// Commit rows to the outbound queue before writing them. The caller's `on_sent`
// hook runs only after the rows were written and removed from the core queue.
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
    network_queues::enqueue_outbound(store, &rows)?;
    let queued = network_queues::claim_outbound_for_target(store, target, rows.len())?;
    for row in &queued {
        write_frame(stream, &row.bytes).map_err(|err| format!("write frame: {err}"))?;
    }
    network_queues::delete_outbound(store, &queued)?;
    on_sent(&queued, value)?;
    report.sent_frames += queued.len();
    Ok(())
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
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()
}

// The frame format is fixed and intentionally not self-describing. Type tags,
// encryption, and validation are all properties of the bytes carried inside the
// frame and are owned above this layer.
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
