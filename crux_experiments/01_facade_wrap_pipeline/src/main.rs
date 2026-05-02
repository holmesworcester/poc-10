fn main() {
    let run = facade_wrap_pipeline::run_demo_shell(3, 128);

    println!("effects: {}", run.effect_order.join(" -> "));
    for line in run.printed {
        println!("{line}");
    }
}
