use std::env;
use std::path::PathBuf;

use topo::core::cli;
use topo::protocol;

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let (db_path, command_args) = parse_global_args(args)?;
    let mut context = protocol::cli::Context::open(db_path)?;
    let commands = protocol::cli::commands();
    let output = cli::run(&commands, &mut context, &command_args)?;
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

fn parse_global_args(args: Vec<String>) -> Result<(PathBuf, Vec<String>), String> {
    let mut iter = args.into_iter();
    let mut db_path = None;
    let mut command_args = Vec::new();

    while let Some(arg) = iter.next() {
        if arg == "--db" {
            db_path = iter.next().map(PathBuf::from);
        } else {
            command_args.push(arg);
            command_args.extend(iter);
            break;
        }
    }

    let db_path = db_path.ok_or_else(|| "missing --db PATH".to_string())?;
    Ok((db_path, command_args))
}
