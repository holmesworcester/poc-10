#[test]
fn normal_cargo_test_runs_the_rust_harness_serially() {
    assert_eq!(
        std::env::var("RUST_TEST_THREADS").as_deref(),
        Ok("1"),
        "poc-10 daemon/network integration tests are timing-sensitive under \
         parallel harness execution; keep normal cargo test runs serial"
    );
}
