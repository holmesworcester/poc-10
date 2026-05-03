use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use topo::event_modules::Modules;
use topo::kernel;
use topo::store::Store;

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
                let lines = kernel::run_serve(&store, &modules, addr, accept_count)
                    .map_err(|err| format!("serve: {err}"))?;
                for line in lines {
                    println!("{line}");
                }
            } else {
                let lines = kernel::run_sync_routes(&store, &modules)
                    .map_err(|err| format!("sync: {err}"))?;
                for line in lines {
                    println!("{line}");
                }
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
