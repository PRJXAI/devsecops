#![forbid(unsafe_code)]
// A Rust-only negative fixture. It never contacts Docker or a registry.
use std::{env, fs::OpenOptions, io::Write, path::Path};
fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    let root = env::var("DEVSECOPS_FAKE_ROOT").unwrap();
    let mut log = OpenOptions::new().append(true).create(true).open(Path::new(&root).join("commands")).unwrap();
    writeln!(log, "{}", args.join(" ")).unwrap();
    if args.first().map(String::as_str) == Some("run") && env::var_os("DEVSECOPS_FAKE_CONTRACT").is_some() {
        println!("{{\"synthetic\":\"complete\"}}");
        if env::var("DEVSECOPS_FAKE_CONTRACT").unwrap() != "empty" { eprintln!("SYNTHETIC_PRIVATE_DIAGNOSTIC"); }
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
        if name == "docker-arm64" {
            match env::var("DEVSECOPS_FAKE_LOAD").unwrap().as_str() {
                "wrong" => println!("Loaded image ID: sha256:{}", "f".repeat(64)),
                "multiple" => println!("Loaded image ID: {id}\nLoaded image ID: {id}"),
                _ => println!("preexisting cached {id}"),
            }
        } else { println!("Loaded image ID: {id}"); }
    } else if args.get(1).map(String::as_str) == Some("inspect") {
        let id = args.last().unwrap();
        let arch = if id.as_bytes().last() == Some(&b'a') { "amd64" } else { "arm64" };
        println!("{id} 65532:65532 linux {arch} https://github.com/PRJXAI/devsecops {}", env::var("GITHUB_SHA").unwrap());
    } else if args.get(1).map(String::as_str) == Some("tag") {
        // Succeed so the old interleaved load/push flow would be caught at push.
    } else { std::process::exit(9); }
}
