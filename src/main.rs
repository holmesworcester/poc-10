use std::env;

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    if matches!(argv.first().map(String::as_str), Some("poc10-demo")) {
        if let Err(err) = topo::poc10_demo::run() {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(err) = topo::core::app::run::<topo::protocol::Protocol>(argv) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
