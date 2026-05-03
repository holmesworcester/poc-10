use std::env;
use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;

use topo::event_modules::Modules;
use topo::store::Store;
use topo::{control_loop, kernel, network, pipeline};

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let (db_path, command) = parse_args(args)?;
    let store = Store::open(db_path).map_err(|err| format!("open store: {err}"))?;
    let modules = Modules::new();

    match command {
        Command::Connect { invite } => {
            let lines = kernel::run_connect(&store, &modules, invite)
                .map_err(|err| format!("connect: {err}"))?;
            for line in lines {
                println!("{line}");
            }
        }
        Command::Invite { public_addr } => {
            let lines = kernel::run_invite(&store, &modules, public_addr)
                .map_err(|err| format!("invite: {err}"))?;
            for line in lines {
                println!("{line}");
            }
        }
        Command::Generate {
            num_events,
            event_size,
        } => {
            let lines = kernel::run_generate(&store, &modules, num_events, event_size)
                .map_err(|err| format!("generate: {err}"))?;
            for line in lines {
                println!("{line}");
            }
        }
        Command::Sync {
            listen,
            accept_count,
        } => {
            if let Some(addr) = listen {
                let listener = TcpListener::bind(addr).map_err(|err| format!("listen: {err}"))?;
                println!(
                    "listening: {}",
                    listener.local_addr().map_err(|err| err.to_string())?
                );
                std::io::stdout()
                    .flush()
                    .map_err(|err| format!("flush stdout: {err}"))?;
                let report = serve(&store, &modules, listener, accept_count)
                    .map_err(|err| format!("serve: {err}"))?;
                println!("accepted_connections: {}", report.accepted_connections);
                println!("received_events: {}", report.received_events);
            } else {
                let report = sync_routes(&store, &modules).map_err(|err| format!("sync: {err}"))?;
                println!("routes_synced: {}", report.routes_synced);
                println!("sent_events: {}", report.sent_events);
                println!("received_events: {}", report.received_events);
            }
        }
        Command::Count => {
            let lines =
                kernel::run_count(&store, &modules).map_err(|err| format!("count: {err}"))?;
            for line in lines {
                println!("{line}");
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Connect {
        invite: String,
    },
    Invite {
        public_addr: SocketAddr,
    },
    Generate {
        num_events: usize,
        event_size: usize,
    },
    Sync {
        listen: Option<SocketAddr>,
        accept_count: usize,
    },
    Count,
}

fn parse_args(args: Vec<String>) -> Result<(PathBuf, Command), String> {
    let mut iter = args.into_iter();
    let mut db_path = None;
    let mut rest = Vec::new();

    while let Some(arg) = iter.next() {
        if arg == "--db" {
            db_path = iter.next().map(PathBuf::from);
        } else {
            rest.push(arg);
            rest.extend(iter);
            break;
        }
    }

    let db_path = db_path.ok_or_else(|| usage("missing --db PATH"))?;
    let command = rest.first().ok_or_else(|| usage("missing command"))?;
    let parsed = match command.as_str() {
        "connect" => {
            if rest.len() != 2 {
                return Err(usage("connect requires INVITE_LINK"));
            }
            Command::Connect {
                invite: rest[1].clone(),
            }
        }
        "invite" => {
            let mut public_addr = None;
            let mut idx = 1;
            while idx < rest.len() {
                match rest[idx].as_str() {
                    "--public-addr" => {
                        public_addr = Some(
                            rest.get(idx + 1)
                                .ok_or_else(|| usage("invite requires --public-addr ADDR"))?
                                .parse::<SocketAddr>()
                                .map_err(|_| usage("invite requires --public-addr ADDR"))?,
                        );
                        idx += 2;
                    }
                    other => return Err(usage(&format!("unknown invite option `{other}`"))),
                }
            }
            Command::Invite {
                public_addr: public_addr
                    .ok_or_else(|| usage("invite requires --public-addr ADDR"))?,
            }
        }
        "generate" => {
            let num_events = parse_usize(rest.get(1), "generate requires NUM_EVENTS EVENT_SIZE")?;
            let event_size = parse_usize(rest.get(2), "generate requires NUM_EVENTS EVENT_SIZE")?;
            Command::Generate {
                num_events,
                event_size,
            }
        }
        "sync" => {
            let mut listen = None;
            let mut accept_count = 1usize;
            let mut idx = 1;
            while idx < rest.len() {
                match rest[idx].as_str() {
                    "--listen" => {
                        let ip = rest
                            .get(idx + 1)
                            .ok_or_else(|| usage("sync --listen requires IP PORT"))?;
                        let port = rest
                            .get(idx + 2)
                            .ok_or_else(|| usage("sync --listen requires IP PORT"))?;
                        listen = Some(
                            format!("{ip}:{port}")
                                .parse::<SocketAddr>()
                                .map_err(|_| usage("sync --listen requires IP PORT"))?,
                        );
                        idx += 3;
                    }
                    "--accept" => {
                        accept_count = parse_usize(
                            rest.get(idx + 1),
                            "sync --accept requires a positive integer",
                        )?;
                        idx += 2;
                    }
                    other => return Err(usage(&format!("unknown sync option `{other}`"))),
                }
            }
            if accept_count == 0 {
                return Err(usage("sync --accept requires a positive integer"));
            }
            Command::Sync {
                listen,
                accept_count,
            }
        }
        "count" | "status" => Command::Count,
        other => return Err(usage(&format!("unknown command `{other}`"))),
    };

    Ok((db_path, parsed))
}

fn parse_usize(value: Option<&String>, message: &str) -> Result<usize, String> {
    let value = value.ok_or_else(|| usage(message))?;
    let parsed = value.parse::<usize>().map_err(|_| usage(message))?;
    if parsed == 0 {
        return Err(usage(message));
    }
    Ok(parsed)
}

fn usage(message: &str) -> String {
    format!(
        "{message}\nusage:\n  topo --db PATH invite --public-addr ADDR\n  topo --db PATH connect INVITE_LINK\n  topo --db PATH generate NUM_EVENTS EVENT_SIZE_BYTES\n  topo --db PATH sync [--listen IP PORT --accept N]\n  topo --db PATH count"
    )
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ServeReport {
    accepted_connections: usize,
    received_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CliSyncReport {
    routes_synced: usize,
    sent_events: usize,
    received_events: usize,
}

fn serve(
    store: &Store,
    modules: &Modules,
    listener: TcpListener,
    accept_count: usize,
) -> Result<ServeReport, String> {
    let mut report = ServeReport::default();
    for _ in 0..accept_count {
        let (mut stream, peer_addr) = listener
            .accept()
            .map_err(|err| format!("accept tcp stream: {err}"))?;
        let first_frame =
            network::read_frame(&mut stream).map_err(|err| format!("read first frame: {err}"))?;
        let stream_report = drive_stream(
            store,
            modules,
            &mut stream,
            pipeline::FrameMetadata {
                origin: peer_addr,
                remember_origin: false,
            },
            Some(first_frame),
        )?;
        report.received_events += stream_report.received_events;
        report.accepted_connections += 1;
    }
    Ok(report)
}

fn sync_routes(store: &Store, modules: &Modules) -> Result<CliSyncReport, String> {
    control_loop::drain_until_idle(store, modules, control_loop::DEFAULT_READY_BATCH)
        .map_err(|err| format!("drain ready events before sync: {err}"))?;
    let mut report = CliSyncReport::default();
    let start = modules.start_sync(store)?;
    let (started, _) = pipeline::run_command(store, modules, start)
        .map_err(|err| format!("record sync frames: {err}"))?;
    report.sent_events += started.sent_events;
    for outbound in modules.drain_outbox_routes(store)? {
        let mut stream =
            network::connect(outbound.target).map_err(|err| format!("open tcp stream: {err}"))?;
        report.sent_events += outbound.sent_events;
        network::write_frames(&mut stream, outbound.outgoing)?;
        modules.mark_outbox_sent(store, outbound.sent_outbox)?;
        let stream_report = drive_stream(
            store,
            modules,
            &mut stream,
            pipeline::FrameMetadata {
                origin: outbound.target,
                remember_origin: false,
            },
            None,
        )?;
        report.routes_synced += 1;
        report.sent_events += stream_report.sent_events;
        report.received_events += stream_report.received_events;
    }
    Ok(report)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StreamReport {
    established_connections: usize,
    sent_events: usize,
    received_events: usize,
}

fn drive_stream(
    store: &Store,
    modules: &Modules,
    stream: &mut TcpStream,
    metadata: pipeline::FrameMetadata,
    first_frame: Option<Vec<u8>>,
) -> Result<StreamReport, String> {
    let mut report = StreamReport::default();
    if let Some(bytes) = first_frame {
        let result = pipeline::ingest_frame(store, modules, metadata, bytes)?;
        control_loop::drain_until_idle(store, modules, control_loop::DEFAULT_READY_BATCH)
            .map_err(|err| format!("drain ready events: {err}"))?;
        apply_stream_result(store, modules, stream, &mut report, result)?;
    }
    loop {
        match network::read_frame(stream) {
            Ok(bytes) => {
                let result = pipeline::ingest_frame(store, modules, metadata, bytes)?;
                control_loop::drain_until_idle(store, modules, control_loop::DEFAULT_READY_BATCH)
                    .map_err(|err| format!("drain ready events: {err}"))?;
                apply_stream_result(store, modules, stream, &mut report, result)?;
            }
            Err(err) if is_stream_closed(&err) => break,
            Err(err) => return Err(format!("read frame: {err}")),
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    Ok(report)
}

fn apply_stream_result(
    store: &Store,
    modules: &Modules,
    stream: &mut TcpStream,
    report: &mut StreamReport,
    result: pipeline::IngestResult,
) -> Result<(), String> {
    report.established_connections += result.established_routes;
    report.sent_events += result.sent_events;
    report.received_events += result.received_events;
    let has_outgoing = !result.outgoing.is_empty();
    network::write_frames(stream, result.outgoing)?;
    modules.mark_outbox_sent(store, result.sent_outbox)?;
    if !has_outgoing {
        let _ = stream.shutdown(Shutdown::Write);
    }
    Ok(())
}

fn is_stream_closed(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
    )
}
