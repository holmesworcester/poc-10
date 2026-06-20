use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn fact_families_have_proof_modules() {
    let protocol_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol");
    let mut fact_dirs = Vec::new();
    collect_fact_family_dirs(&protocol_dir, &mut fact_dirs);
    fact_dirs.sort();

    assert!(!fact_dirs.is_empty(), "expected protocol fact families");

    let mut missing = Vec::new();
    for fact_dir in fact_dirs {
        let manifest = fact_dir.with_extension("rs");
        if !fact_dir.join("proofs.rs").is_file() {
            missing.push(format!("missing {}", fact_dir.join("proofs.rs").display()));
        }
        let manifest_text = fs::read_to_string(&manifest)
            .unwrap_or_else(|err| panic!("read {}: {err}", manifest.display()));
        if !manifest_text.contains("pub mod proofs;") {
            missing.push(format!("{} does not declare proofs", manifest.display()));
        }
    }

    assert!(
        missing.is_empty(),
        "fact-family proof module contract failed:\n{}",
        missing.join("\n")
    );
}

fn collect_fact_family_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display())) {
        let entry = entry.unwrap_or_else(|err| panic!("read entry in {}: {err}", dir.display()));
        let path = entry.path();
        if path.is_dir() {
            if path.join("fact.rs").is_file() {
                out.push(path);
            } else {
                collect_fact_family_dirs(&path, out);
            }
        }
    }
}
