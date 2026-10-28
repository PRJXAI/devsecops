#![forbid(unsafe_code)]
// A Rust-only negative fixture. It never contacts Docker or a registry.
use std::{env, fs::OpenOptions, io::Write, path::Path};
fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    let root = env::var("DEVSECOPS_FAKE_ROOT").unwrap();
    let mut log = OpenOptions::new().append(true).create(true).open(Path::new(&root).join("commands")).unwrap();
    writeln!(log, "{}", args.join(" ")).unwrap();
    if env::var_os("DEVSECOPS_FAKE_PREPARE").is_some()
        && matches!(args.first().map(String::as_str), Some("pull" | "run" | "rm" | "--host")) {
        let mode = env::var("DEVSECOPS_FAKE_PREPARE").unwrap();
        let fail = match args[0].as_str() {
            "pull" => mode == "pull",
            "run" => (mode == "refresh" && args.iter().any(|a| a == "update"))
                || (mode == "status" && args.iter().any(|a| a == "status")),
            "--host" => true, // Independent per-tool build failure after shared setup.
            _ => false,
        };
        if fail {
            eprintln!("SYNTHETIC_PRIVATE_DIAGNOSTIC");
            std::process::exit(9);
        }
        if args[0] == "run" && args.iter().any(|a| a == "status") {
            println!("{{\"valid\":false,\"schemaVersion\":\"unreviewed\"}}");
        }
    } else if args.first().map(String::as_str) == Some("run") && env::var_os("DEVSECOPS_FAKE_CONTRACT").is_some() {
        println!("{{\"synthetic\":\"complete\"}}");
        let mode = env::var("DEVSECOPS_FAKE_CONTRACT").unwrap();
        if mode.starts_with("precision") {
            eprintln!("[0000]  WARN go binary packages were found but none carry function symbols; go vulnerability matching falls back to module granularity and may report false positives. if scanning an SBOM, regenerate it with symbol capture enabled for more precise results.");
        }
        if mode != "empty" && mode != "precision" { eprintln!("SYNTHETIC_PRIVATE_DIAGNOSTIC"); }
    } else if args.first().map(String::as_str) == Some("rm") && env::var_os("DEVSECOPS_FAKE_CONTRACT").is_some() {
        // Successful owned-container removal, including after analysis rejection.
    } else if args.first().map(String::as_str) == Some("context") {
        println!("unix:///synthetic/docker.sock");
    } else if args.first().map(String::as_str) == Some("info") {
        println!("linux {}", if cfg!(target_arch="aarch64") { "arm64" } else { "amd64" });
    } else if args.get(1).map(String::as_str) == Some("load") {
        let path = Path::new(args.last().unwrap());
        let name = path.file_stem().unwrap().to_str().unwrap();
        let id = std::fs::read_to_string(path.with_extension("id")).unwrap();
        let mode = env::var("DEVSECOPS_FAKE_LOAD").unwrap();
        if name == "docker-arm64" || (name == "syft-arm64" && mode.starts_with("single-") && mode != "single-success") {
            match mode.as_str() {
                "wrong" | "single-wrong" => println!("Loaded image ID: sha256:{}", "f".repeat(64)),
                "multiple" | "single-multiple" => println!("Loaded image ID: {id}\nLoaded image ID: {id}"),
                _ => println!("preexisting cached {id}"),
            }
        } else { println!("Loaded image ID: {id}"); }
    } else if args.get(1).map(String::as_str) == Some("inspect") {
        let id = args.last().unwrap();
        let arch = if id.as_bytes().last() == Some(&b'a') { "amd64" } else { "arm64" };
        println!("{id} 65532:65532 linux {arch} https://github.com/PRJXAI/devsecops {}", env::var("GITHUB_SHA").unwrap());
    } else if args.first().map(String::as_str) == Some("buildx") && matches!(env::var("DEVSECOPS_FAKE_LOAD").as_deref(), Ok("single-success" | "single-risk-success")) {
        if args.get(2).map(String::as_str) == Some("inspect") {
            let reference = args.last().unwrap();
            let tool = if env::var("DEVSECOPS_FAKE_LOAD").unwrap() == "single-risk-success" { "gitleaks" } else { "syft" };
            assert!(reference.starts_with(&format!("ghcr.io/prjxai/devsecops/{tool}")));
            if args.iter().any(|arg| arg == "--raw") {
                let id = reference.split_once('@').unwrap().1;
                let member = ["amd64", "arm64", "index"].into_iter().find(|member| std::fs::read_to_string(Path::new(&root).join(format!("registry-{member}.id"))).unwrap() == id).unwrap();
                print!("{}", std::fs::read_to_string(Path::new(&root).join(format!("registry-{member}.json"))).unwrap());
            } else {
                let member = if reference.ends_with("-amd64") { "amd64" } else if reference.ends_with("-arm64") { "arm64" } else { "index" };
                let id = std::fs::read_to_string(Path::new(&root).join(format!("registry-{member}.id"))).unwrap();
                println!("{{\"digest\":\"{id}\"}}");
            }
        } else { assert_eq!(args[2], "create"); }
    } else if args.get(1).map(String::as_str) == Some("push") && matches!(env::var("DEVSECOPS_FAKE_LOAD").as_deref(), Ok("single-success" | "single-risk-success")) {
        let tool = if env::var("DEVSECOPS_FAKE_LOAD").unwrap() == "single-risk-success" { "gitleaks" } else { "syft" };
        assert!(args.last().unwrap().starts_with(&format!("ghcr.io/prjxai/devsecops/{tool}:")));
    } else if args.get(1).map(String::as_str) == Some("tag") {
        // Succeed so the old interleaved load/push flow would be caught at push.
    } else { std::process::exit(9); }
}
