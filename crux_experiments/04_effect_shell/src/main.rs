use effect_shell_poc::run_demo;

fn main() {
    let (model, transcript, stdout) = run_demo();

    println!("effect transcript:");
    for entry in transcript {
        println!("{entry:?}");
    }
    println!("stdout: {stdout:?}");
    println!("view model: {:?}", model.last);
}
