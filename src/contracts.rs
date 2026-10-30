//! Small, offline consumer contracts. These are not release acceptance or cluster tests.
//! Fixtures are synthetic; cargo-audit separately retrieves public RustSec data.
//! Analysis is offline; reports use the driver's bounded private stdout capture.

use super::{Driver, Result, release};
use serde_json::{Value, json};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

const REPORT_LIMIT: u64 = 8 * 1024 * 1024;

pub(super) fn check(driver: &mut Driver, tool: &str, image: &str) -> Result<()> {
    super::filesystem::check(driver, tool, image)?;
    functional(driver, tool, image)
}

pub(super) fn functional(driver: &mut Driver, tool: &str, image: &str) -> Result<()> {
    match tool {
        "gitleaks" => gitleaks(driver, image),
        "syft" => syft(driver, image),
        "kustomize" => kustomize(driver, image),
        "kubectl" => kubectl(driver, image),
        "docker" => compose(driver, image),
        "grype" => super::grype_contract::check(driver, image),
        "cargo-audit" => super::audit::contract(driver, image),
        "cargo-deny" => Err(
            "cargo-deny functional contract blocked: pinned compiler-free runtime cannot prove Cargo/index/advisory coverage",
        ),
        "k3d" => Err(
            "k3d functional contract blocked: packaged native control-plane and inventory qualification required",
        ),
        _ => Err("unsupported functional contract"),
    }
}

fn mkdir(path: &Path, mode: u32) -> Result<()> {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "refusing stale or unwritable contract directory")?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| "cannot set contract directory permissions")
}

fn fixture(driver: &mut Driver, tool: &str) -> Result<PathBuf> {
    driver.sequence = driver
        .sequence
        .checked_add(1)
        .ok_or("contract sequence exhausted")?;
    let root = driver
        .logs
        .join(format!("contract-{tool}-{}", driver.sequence));
    // The enclosing root stays private. Only the individually mounted input leaf is
    // readable by UID 65532, even when the host has a restrictive umask.
    mkdir(&root, 0o700)?;
    let input = root.join("input");
    mkdir(&input, 0o755)?;
    Ok(input)
}

fn write(path: &Path, contents: &str) -> Result<()> {
    // create_new rejects existing files, including symlinks.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "refusing existing or unwritable contract fixture")?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| "cannot write contract fixture")?;
    file.set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(|_| "cannot grant container fixture read access")
}

fn mount(path: &Path, target: &str, writable: bool) -> Result<String> {
    if !path.is_absolute()
        || !fs::symlink_metadata(path)
            .map_err(|_| "missing contract input directory")?
            .is_dir()
    {
        return Err("contract input must be an absolute nonsymlink directory");
    }
    let source = path
        .to_str()
        .filter(|p| !p.contains([',', '\n', '\r']))
        .ok_or("invalid contract mount path")?;
    Ok(format!(
        "type=bind,source={source},target={target}{}",
        if writable { "" } else { ",readonly" }
    ))
}

// This helper fixes the offline resource/security policy; it is not a configurable
// test runner. The only alternate entrypoint is the packaged Git builtin executable.
fn run(
    driver: &mut Driver,
    image: &str,
    args: &[&str],
    input: Option<&str>,
    git: bool,
    expected_exit: i32,
) -> Result<PathBuf> {
    let identity = driver
        .logs
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("missing contract run identity")?;
    let name = format!("contract-{identity}-{}", driver.sequence);
    let mut command = vec![
        "run",
        "--pull=never",
        "--name",
        &name,
        "--network=none",
        "--read-only",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--memory=3g",
        "--memory-swap=3g",
        "--cpus=2",
        "--pids-limit=128",
        "--ulimit=nofile=256:256",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777",
        "--workdir=/tmp",
        "--env=HOME=/tmp",
        "--env=XDG_CONFIG_HOME=/tmp/config",
        "--env=XDG_CACHE_HOME=/tmp/cache",
        "--env=SYFT_CHECK_FOR_APP_UPDATE=false",
        "--env=SYFT_CACHE_DIR=/tmp/cache/syft",
        "--env=GIT_CONFIG_NOSYSTEM=1",
        "--env=GIT_CONFIG_SYSTEM=/dev/null",
        "--env=GIT_CONFIG_GLOBAL=/dev/null",
        "--env=GIT_CONFIG_COUNT=5",
        "--env=GIT_CONFIG_KEY_0=safe.directory",
        "--env=GIT_CONFIG_VALUE_0=/fixture",
        "--env=GIT_CONFIG_KEY_1=safe.directory",
        "--env=GIT_CONFIG_VALUE_1=/history",
        "--env=GIT_CONFIG_KEY_2=core.hooksPath",
        "--env=GIT_CONFIG_VALUE_2=/dev/null",
        "--env=GIT_CONFIG_KEY_3=protocol.allow",
        "--env=GIT_CONFIG_VALUE_3=never",
        "--env=GIT_CONFIG_KEY_4=credential.helper",
        "--env=GIT_CONFIG_VALUE_4=",
        "--env=GIT_ATTR_NOSYSTEM=1",
        "--env=GIT_TERMINAL_PROMPT=0",
        "--env=GIT_NO_REPLACE_OBJECTS=1",
        "--env=KUBECONFIG=/dev/null",
        "--env=KUBECTL_KUBERC=false",
        "--env=DOCKER_CONFIG=/tmp/docker",
        "--env=DOCKER_HOST=unix:///tmp/no-daemon.sock",
    ];
    if let Some(input) = input {
        command.extend(["--mount", input]);
    }
    if git {
        command.extend(["--entrypoint", "/usr/bin/git"]);
    }
    command.push(image);
    command.extend_from_slice(args);
    let result = driver.docker_exit(&command, 120, false, expected_exit);
    // Cleanup must ignore cancellation, including after run spawn/exit failures.
    let cleanup = driver.docker_exit(&["rm", "--force", &name], 15, true, 0);
    let output = match (result, cleanup) {
        (Err(_), Err(_)) => Err("contract failed and container cleanup was not confirmed"),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(_)) => Err("contract container cleanup failed; private logs retained"),
        (Ok(_), Ok(_)) if driver.cancelled.load(Ordering::Relaxed) => Err("contract cancelled"),
        (Ok(path), Ok(_)) => Ok(path),
    }?;
    // Git setup has expected chatter; positive analyses must be diagnostic-free.
    // Gitleaks finding exits retain their separate two-stream redaction check.
    if !git && expected_exit == 0 && !super::captured_stderr(&output)?.is_empty() {
        return Err("functional analysis emitted diagnostics; private logs retained");
    }
    Ok(output)
}

fn report(path: &Path) -> Result<Value> {
    let data = release::bytes(path, REPORT_LIMIT)?;
    serde_json::from_slice(&data).map_err(|_| "malformed contract JSON report")
}

fn git(driver: &mut Driver, image: &str, input: &str, args: &[&str]) -> Result<PathBuf> {
    let mut command = vec![
        "-c",
        "user.name=Synthetic Contract",
        "-c",
        "user.email=contract@example.invalid",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "tag.gpgSign=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "protocol.allow=never",
        "-c",
        "credential.helper=",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
        "-c",
        "safe.directory=/fixture",
        "-c",
        "safe.directory=/history",
    ];
    command.extend_from_slice(args);
    run(driver, image, &command, Some(input), true, 0)
}

fn synthetic_token() -> Result<String> {
    let mut random = [0u8; 36];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(|_| "cannot generate synthetic secret fixture")?;
    let alphabet = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let payload: String = random
        .iter()
        .map(|byte| char::from(alphabet[usize::from(*byte) % alphabet.len()]))
        .collect();
    // The full value deliberately has an invalid PAT length. Its ghp_-shaped
    // substring is randomly generated here, never issued, and never validated.
    Ok(format!("ghp_{payload} SYNTHETIC_NEVER_VALID"))
}

fn redacted_findings(data: &[u8], diagnostics: &[u8], token: &str, findings: bool) -> Result<()> {
    let core = token.get(..40).ok_or("invalid synthetic token fixture")?;
    for output in [data, diagnostics] {
        if output
            .windows(core.len())
            .any(|bytes| bytes == core.as_bytes())
            || output.windows(4).any(|bytes| bytes == b"ghp_")
        {
            return Err("Gitleaks redaction failed; private logs retained");
        }
    }
    if !diagnostics.iter().all(u8::is_ascii_whitespace) {
        return Err("Gitleaks emitted diagnostics; private logs retained");
    }
    let report: Value =
        serde_json::from_slice(data).map_err(|_| "malformed Gitleaks contract report")?;
    // Gitleaks may encode an empty Go slice as null; only an exact clean exit
    // reaches this branch. Positive controls still require real redacted entries.
    if !findings && report.is_null() {
        return Ok(());
    }
    let entries = report
        .as_array()
        .ok_or("Gitleaks report must contain a findings array")?;
    if !findings {
        return if entries.is_empty() {
            Ok(())
        } else {
            Err("Gitleaks clean control unexpectedly reported findings")
        };
    }
    if !entries.iter().any(|entry| {
        entry["RuleID"] == "github-pat"
            && entry["File"]
                .as_str()
                .is_some_and(|s| s.ends_with("seed.txt"))
    }) || entries.iter().any(|entry| {
        entry["Secret"] != "REDACTED"
            || !entry["Match"]
                .as_str()
                .is_some_and(|s| s.contains("REDACTED"))
    }) {
        return Err("Gitleaks did not report the expected fully redacted synthetic finding");
    }
    Ok(())
}

fn leaks(
    driver: &mut Driver,
    image: &str,
    input: &str,
    mode: &[&str],
    token: &str,
    findings: bool,
) -> Result<()> {
    let mut args = mode.to_vec();
    args.extend([
        "--no-banner",
        "--log-level=error",
        "--redact=100",
        "--report-format=json",
        "--report-path=/dev/stdout",
        "--gitleaks-ignore-path=/dev/null",
        "--exit-code=1",
    ]);
    let output = run(
        driver,
        image,
        &args,
        Some(input),
        false,
        i32::from(findings),
    )?;
    // The report is stdout, not a writable host output mount. Check the actual
    // captured stdout AND stderr, not just the parsed Secret field.
    redacted_findings(
        &release::bytes(&output, REPORT_LIMIT)?,
        &super::captured_stderr(&output)?,
        token,
        findings,
    )
}

fn gitleaks(driver: &mut Driver, image: &str) -> Result<()> {
    let input = fixture(driver, "gitleaks")?;
    let token = synthetic_token()?;
    write(
        &input.join("seed.txt"),
        &format!("synthetic_token = {token}\n"),
    )?;
    write(
        &input.join("README.txt"),
        "Only synthetic offline fixtures.\n",
    )?;
    let readonly = mount(&input, "/fixture", false)?;
    leaks(driver, image, &readonly, &["dir", "/fixture"], &token, true)?;

    // Only Git initialization/history writes get a writable mount. The private
    // enclosing root remains 0700; Git needs write access to this mounted leaf.
    fs::set_permissions(&input, fs::Permissions::from_mode(0o777))
        .map_err(|_| "cannot grant synthetic Git initialization access")?;
    let writable = mount(&input, "/fixture", true)?;
    git(
        driver,
        image,
        &writable,
        &[
            "init",
            "--template=",
            "--initial-branch=retained-history",
            "/fixture",
        ],
    )?;
    for args in [
        vec!["-C", "/fixture", "add", "--", "seed.txt", "README.txt"],
        vec![
            "-C",
            "/fixture",
            "commit",
            "--no-gpg-sign",
            "-m",
            "synthetic seed",
        ],
        vec!["-C", "/fixture", "rm", "--", "seed.txt"],
        vec![
            "-C",
            "/fixture",
            "commit",
            "--no-gpg-sign",
            "-m",
            "delete synthetic seed",
        ],
        vec!["-C", "/fixture", "checkout", "--orphan", "clean-head"],
        vec![
            "-C",
            "/fixture",
            "commit",
            "--no-gpg-sign",
            "--allow-empty",
            "-m",
            "unrelated clean head",
        ],
    ] {
        git(driver, image, &writable, &args)?;
    }
    leaks(
        driver,
        image,
        &readonly,
        &["dir", "/fixture"],
        &token,
        false,
    )?;
    git(
        driver,
        image,
        &writable,
        &["-C", "/fixture", "config", "core.bare", "true"],
    )?;
    fs::set_permissions(&input, fs::Permissions::from_mode(0o755))
        .map_err(|_| "cannot seal synthetic Git input")?;
    // Mount ONLY .git: no caller repository, remote helper, worktree or socket.
    let bare = mount(&input.join(".git"), "/history", false)?;
    let output = git(
        driver,
        image,
        &bare,
        &["--git-dir=/history", "rev-parse", "--is-bare-repository"],
    )?;
    if release::bytes(&output, REPORT_LIMIT)? != b"true\n" {
        return Err("synthetic Git history was not bare");
    }
    // HEAD is an unrelated orphan. A scanner ignoring --all cannot satisfy the
    // second control: the deleted seed exists only on retained-history.
    leaks(
        driver,
        image,
        &bare,
        &["git", "/history", "--log-opts=HEAD"],
        &token,
        false,
    )?;
    leaks(
        driver,
        image,
        &bare,
        &["git", "/history", "--log-opts=--all"],
        &token,
        true,
    )
}

const PACKAGES: [(&str, &str, &str, &str); 4] = [
    ("itoa", "1.0.18", "rust-crate", "cargo"),
    ("memchr", "2.8.3", "rust-crate", "cargo"),
    ("is-number", "7.0.0", "npm", "npm"),
    ("minimist", "1.2.8", "npm", "npm"),
];

fn syft_report(value: &Value, format: &str) -> Result<()> {
    let entries = match format {
        "syft-json"
            if value.pointer("/source/type").and_then(Value::as_str) == Some("directory") =>
        {
            value.get("artifacts").and_then(Value::as_array)
        }
        "cyclonedx-json" if value["bomFormat"] == "CycloneDX" => {
            value.get("components").and_then(Value::as_array)
        }
        "spdx-json" if value["spdxVersion"] == "SPDX-2.3" => {
            value.get("packages").and_then(Value::as_array)
        }
        _ => None,
    }
    .ok_or("Syft report has the wrong format or source")?;
    for (name, version, kind, ecosystem) in PACKAGES {
        let purl = format!("pkg:{ecosystem}/{name}@{version}");
        if !entries.iter().any(|entry| {
            if entry["name"] != name {
                return false;
            }
            match format {
                "syft-json" => {
                    entry["version"] == version
                        && entry["type"] == kind
                        && entry["purl"]
                            .as_str()
                            .is_some_and(|s| s == purl || s.starts_with(&format!("{purl}?")))
                        && entry["locations"].as_array().is_some_and(|locations| {
                            locations.iter().any(|location| {
                                location["path"].as_str().is_some_and(|path| {
                                    path.ends_with(if ecosystem == "cargo" {
                                        "/Cargo.lock"
                                    } else {
                                        "/package-lock.json"
                                    })
                                })
                            })
                        })
                }
                "cyclonedx-json" => {
                    entry["version"] == version
                        && entry["purl"]
                            .as_str()
                            .is_some_and(|s| s == purl || s.starts_with(&format!("{purl}?")))
                }
                "spdx-json" => {
                    entry["versionInfo"] == version
                        && entry["externalRefs"].as_array().is_some_and(|refs| {
                            refs.iter().any(|reference| {
                                reference["referenceType"] == "purl"
                                    && reference["referenceLocator"].as_str().is_some_and(|s| {
                                        s == purl || s.starts_with(&format!("{purl}?"))
                                    })
                            })
                        })
                }
                _ => false,
            }
        }) {
            return Err("Syft omitted or misidentified a required workspace/development package");
        }
    }
    Ok(())
}

fn syft(driver: &mut Driver, image: &str) -> Result<()> {
    let input = fixture(driver, "syft")?;
    mkdir(&input.join("crates"), 0o755)?;
    mkdir(&input.join("crates/app"), 0o755)?;
    mkdir(&input.join("crates/app/src"), 0o755)?;
    mkdir(&input.join("npm"), 0o755)?;
    write(
        &input.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/app\"]\nresolver = \"2\"\n",
    )?;
    write(
        &input.join("crates/app/Cargo.toml"),
        "[package]\nname = \"synthetic-app\"\nversion = \"0.0.0\"\nedition = \"2021\"\n[dependencies]\nitoa = \"=1.0.18\"\n[dev-dependencies]\nmemchr = \"=2.8.3\"\n",
    )?;
    write(
        &input.join("crates/app/src/lib.rs"),
        "// Synthetic scan input; never compiled.\n",
    )?;
    // Real versions/checksums, copied from this repository's lockfile;
    // no dependency source/cache retrieval is needed to catalog these locks.
    write(
        &input.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "synthetic-app"
version = "0.0.0"
dependencies = ["itoa", "memchr"]

[[package]]
name = "itoa"
version = "1.0.18"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682"

[[package]]
name = "memchr"
version = "2.8.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98"
"#,
    )?;
    write(
        &input.join("npm/package.json"),
        r#"{"name":"synthetic-node","version":"0.0.0","private":true,"dependencies":{"is-number":"7.0.0"},"devDependencies":{"minimist":"1.2.8"}}"#,
    )?;
    write(
        &input.join("npm/package-lock.json"),
        r#"{
  "name":"synthetic-node", "version":"0.0.0", "lockfileVersion":3, "requires":true,
  "packages":{
    "":{"name":"synthetic-node","version":"0.0.0","dependencies":{"is-number":"7.0.0"},"devDependencies":{"minimist":"1.2.8"}},
    "node_modules/is-number":{"version":"7.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz","license":"MIT"},
    "node_modules/minimist":{"version":"1.2.8","resolved":"https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz","dev":true,"license":"MIT"}
  }
}"#,
    )?;
    let input = mount(&input, "/fixture", false)?;
    // One stdout format per invocation; a successful empty/irrelevant catalog fails.
    for format in ["syft-json", "cyclonedx-json", "spdx-json"] {
        let output = run(
            driver,
            image,
            &["scan", "dir:/fixture", "--quiet", "--output", format],
            Some(&input),
            false,
            0,
        )?;
        syft_report(&report(&output)?, format)?;
    }
    Ok(())
}

const CONFIGMAP: &str = "apiVersion: v1\ndata:\n  mode: synthetic\nkind: ConfigMap\nmetadata:\n  name: contract-settings\n  namespace: offline-contract";
const DEPLOYMENT: &str = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: contract-app\n  namespace: offline-contract\nspec:\n  replicas: 1\n  selector:\n    matchLabels:\n      app: synthetic\n  template:\n    metadata:\n      labels:\n        app: synthetic\n    spec:\n      containers:\n      - envFrom:\n        - configMapRef:\n            name: contract-settings\n        image: example.invalid/contract:never-pull\n        name: app";

fn rendered(data: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(data).map_err(|_| "kustomize emitted non-UTF8 output")?;
    let docs: Vec<_> = text.trim().split("\n---\n").collect();
    // Exact small documents, not substring checks or an invented YAML parser.
    if docs.len() != 2 || !docs.contains(&CONFIGMAP) || !docs.contains(&DEPLOYMENT) {
        return Err("kustomize did not render the expected transformed deployment/configmap");
    }
    Ok(())
}

fn kustomize(driver: &mut Driver, image: &str) -> Result<()> {
    let input = fixture(driver, "kustomize")?;
    write(
        &input.join("kustomization.yaml"),
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nnamespace: offline-contract\nnamePrefix: contract-\nresources:\n- deployment.yaml\nconfigMapGenerator:\n- name: settings\n  literals:\n  - mode=synthetic\ngeneratorOptions:\n  disableNameSuffixHash: true\n",
    )?;
    write(
        &input.join("deployment.yaml"),
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  replicas: 1\n  selector:\n    matchLabels:\n      app: synthetic\n  template:\n    metadata:\n      labels:\n        app: synthetic\n    spec:\n      containers:\n      - name: app\n        image: example.invalid/contract:never-pull\n        envFrom:\n        - configMapRef:\n            name: settings\n",
    )?;
    let input = mount(&input, "/fixture", false)?;
    let output = run(
        driver,
        image,
        &["build", "/fixture"],
        Some(&input),
        false,
        0,
    )?;
    rendered(&release::bytes(&output, REPORT_LIMIT)?)
}

fn client_configmap(value: &Value) -> Result<()> {
    if value["apiVersion"] != "v1"
        || value["kind"] != "ConfigMap"
        || value.pointer("/metadata/name").and_then(Value::as_str) != Some("offline-config")
        || value.pointer("/metadata/namespace").and_then(Value::as_str) != Some("offline-contract")
        || value["data"] != json!({"mode": "synthetic"})
    {
        return Err("kubectl client dry-run did not produce the expected configmap");
    }
    Ok(())
}

fn kubectl(driver: &mut Driver, image: &str) -> Result<()> {
    let output = run(
        driver,
        image,
        &[
            "--kubeconfig=/dev/null",
            "--request-timeout=5s",
            "--namespace=offline-contract",
            "create",
            "configmap",
            "offline-config",
            "--from-literal=mode=synthetic",
            "--dry-run=client",
            "--output=json",
        ],
        None,
        false,
        0,
    )?;
    client_configmap(&report(&output)?)
}

fn compose_config(value: &Value) -> Result<()> {
    let services = value["services"]
        .as_object()
        .ok_or("Compose did not emit a services object")?;
    let service = &value["services"]["offline-worker"];
    if value["name"] != "offline-contract"
        || services.len() != 1
        || service["image"] != "example.invalid/contract:never-pull"
        || service["command"] != json!(["fixture", "only"])
        || service["network_mode"] != "none"
        || service["read_only"] != true
        || service["user"] != "65532:65532"
    {
        return Err("Compose did not normalize the expected synthetic service");
    }
    Ok(())
}

fn compose(driver: &mut Driver, image: &str) -> Result<()> {
    let input = fixture(driver, "docker")?;
    write(
        &input.join("compose.yaml"),
        "services:\n  offline-worker:\n    image: example.invalid/contract:never-pull\n    command: [fixture, only]\n    network_mode: none\n    read_only: true\n    user: '65532:65532'\n",
    )?;
    let input = mount(&input, "/fixture", false)?;
    let args = [
        "compose",
        "--project-name=offline-contract",
        "--file=/fixture/compose.yaml",
        "config",
        "--no-interpolate",
        "--no-env-resolution",
    ];
    let mut command = args.to_vec();
    command.push("--format=json");
    let output = run(driver, image, &command, Some(&input), false, 0)?;
    compose_config(&report(&output)?)?;
    let mut command = args.to_vec();
    command.push("--services");
    let output = run(driver, image, &command, Some(&input), false, 0)?;
    if release::bytes(&output, REPORT_LIMIT)? != b"offline-worker\n" {
        return Err("Compose services control did not identify the synthetic service");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory(format: &str) -> Value {
        let entries: Vec<_> = PACKAGES.iter().map(|(name, version, kind, ecosystem)| {
            let purl = format!("pkg:{ecosystem}/{name}@{version}");
            match format {
                "syft-json" => json!({"name":name,"version":version,"type":kind,"purl":purl,"locations":[{"path":if *ecosystem == "cargo" {"/Cargo.lock"} else {"/npm/package-lock.json"}}]}),
                "cyclonedx-json" => json!({"name":name,"version":version,"purl":purl}),
                "spdx-json" => json!({"name":name,"versionInfo":version,"externalRefs":[{"referenceType":"purl","referenceLocator":purl}]}),
                _ => unreachable!(),
            }
        }).collect();
        match format {
            "syft-json" => json!({"source":{"type":"directory"},"artifacts":entries}),
            "cyclonedx-json" => json!({"bomFormat":"CycloneDX","components":entries}),
            "spdx-json" => json!({"spdxVersion":"SPDX-2.3","packages":entries}),
            _ => unreachable!(),
        }
    }

    #[test]
    fn syft_requires_real_versions_and_both_development_packages_in_every_format() {
        for (format, field, version_key) in [
            ("syft-json", "artifacts", "version"),
            ("cyclonedx-json", "components", "version"),
            ("spdx-json", "packages", "versionInfo"),
        ] {
            let good = inventory(format);
            assert!(syft_report(&good, format).is_ok());
            for index in 0..PACKAGES.len() {
                let mut missing = good.clone();
                missing[field].as_array_mut().unwrap().remove(index);
                assert!(syft_report(&missing, format).is_err());
                let mut wrong = good.clone();
                wrong[field][index][version_key] = json!("0.0.0");
                assert!(syft_report(&wrong, format).is_err());
            }
            assert!(syft_report(&json!({}), format).is_err());
        }
    }

    #[test]
    fn syft_rejects_wrong_source_location_and_package_identity() {
        let mut value = inventory("syft-json");
        value["source"]["type"] = json!("image");
        assert!(syft_report(&value, "syft-json").is_err());
        let mut value = inventory("syft-json");
        value["artifacts"][0]["locations"] = json!([]);
        assert!(syft_report(&value, "syft-json").is_err());
        let mut value = inventory("syft-json");
        value["artifacts"][0]["purl"] = json!("pkg:npm/itoa@1.0.18");
        assert!(syft_report(&value, "syft-json").is_err());
    }

    #[test]
    fn gitleaks_checks_redacted_fields_and_both_captured_streams() {
        let token = format!("ghp_{} SYNTHETIC_NEVER_VALID", "aB09".repeat(9));
        let good = json!([{"RuleID":"github-pat","File":"seed.txt","Secret":"REDACTED","Match":"synthetic_token = REDACTED"}]);
        let data = serde_json::to_vec(&good).unwrap();
        assert!(redacted_findings(&data, b"", &token, true).is_ok());
        assert!(redacted_findings(&data, token.as_bytes(), &token, true).is_err());
        let mut leak = good.clone();
        leak[0]["Match"] = json!(&token);
        assert!(redacted_findings(&serde_json::to_vec(&leak).unwrap(), b"", &token, true).is_err());
        let mut wrong = good.clone();
        wrong[0]["Secret"] = json!("partially-redacted");
        assert!(
            redacted_findings(&serde_json::to_vec(&wrong).unwrap(), b"", &token, true).is_err()
        );
        assert!(redacted_findings(b"[]", b"", &token, true).is_err());
        assert!(redacted_findings(b"[]", b"", &token, false).is_ok());
        assert!(redacted_findings(b"null", b"", &token, false).is_ok());
        assert!(redacted_findings(b"null", b"", &token, true).is_err());
        assert!(redacted_findings(&data, b"", &token, false).is_err());
        assert!(redacted_findings(b"{}", b"", &token, false).is_err());
    }

    #[test]
    fn kustomize_requires_two_exact_transformed_objects() {
        let good = format!("{CONFIGMAP}\n---\n{DEPLOYMENT}\n");
        assert!(rendered(good.as_bytes()).is_ok());
        assert!(rendered(CONFIGMAP.as_bytes()).is_err());
        assert!(rendered(good.replace("contract-settings", "settings").as_bytes()).is_err());
        assert!(rendered(format!("{good}---\n{CONFIGMAP}\n").as_bytes()).is_err());
    }

    #[test]
    fn kubectl_requires_client_object_identity_and_data() {
        let good = json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"offline-config","namespace":"offline-contract"},"data":{"mode":"synthetic"}});
        assert!(client_configmap(&good).is_ok());
        let mut wrong = good.clone();
        wrong["metadata"]["namespace"] = json!("default");
        assert!(client_configmap(&wrong).is_err());
        let mut wrong = good.clone();
        wrong["data"] = json!({});
        assert!(client_configmap(&wrong).is_err());
        assert!(client_configmap(&json!({})).is_err());
    }

    #[test]
    #[ignore = "Rust-only subprocess fixture invoked by the active capture regression test"]
    fn contract_stderr_fixture() {
        let root = PathBuf::from(std::env::var_os("DEVSECOPS_FAKE_ROOT").unwrap());
        let mode = std::env::var("DEVSECOPS_FAKE_CONTRACT").unwrap();
        let mut driver = Driver::new().unwrap();
        let output = run(
            &mut driver,
            &format!("sha256:{}", "a".repeat(64)),
            &["synthetic"],
            None,
            mode == "git-chatter",
            0,
        );
        if mode == "diagnostic" {
            assert!(output.is_err());
        } else {
            assert_eq!(
                report(&output.unwrap()).unwrap(),
                json!({"synthetic":"complete"})
            );
        }
        let commands = fs::read_to_string(root.join("commands")).unwrap();
        assert_eq!(commands.lines().count(), 2);
        assert!(commands.lines().last().unwrap().starts_with("rm --force "));
    }

    #[test]
    fn exit_zero_valid_output_with_diagnostics_cannot_pass_an_analysis_contract() {
        let mut driver = Driver::new().unwrap();
        let bin = driver.logs.join("bin");
        fs::create_dir(&bin).unwrap();
        let mut compile = std::process::Command::new("rustc");
        compile
            .args(["--edition=2024", "--crate-name", "fake_docker"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/docker.rs"))
            .arg("-o")
            .arg(bin.join("docker"));
        driver.execute(compile, 60, false, 0).unwrap();
        let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        )))
        .unwrap();
        for mode in ["empty", "diagnostic", "git-chatter"] {
            let _ = fs::remove_file(driver.logs.join("commands"));
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "contracts::tests::contract_stderr_fixture",
                    "--ignored",
                ])
                .env("PATH", &path)
                .env("DEVSECOPS_FAKE_ROOT", &driver.logs)
                .env("DEVSECOPS_FAKE_CONTRACT", mode);
            driver.execute(child, 30, false, 0).unwrap();
        }
    }

    #[test]
    fn compose_requires_normalized_service_not_just_success() {
        let good = json!({"name":"offline-contract","services":{"offline-worker":{"image":"example.invalid/contract:never-pull","command":["fixture","only"],"network_mode":"none","read_only":true,"user":"65532:65532"}}});
        assert!(compose_config(&good).is_ok());
        let mut wrong = good.clone();
        wrong["services"]["offline-worker"]["network_mode"] = json!("host");
        assert!(compose_config(&wrong).is_err());
        let mut wrong = good.clone();
        wrong["services"]["extra"] = json!({});
        assert!(compose_config(&wrong).is_err());
        assert!(compose_config(&json!({})).is_err());
    }
}
