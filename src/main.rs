use std::env;

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    if let Err(err) = topo::match_app::run(argv) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
