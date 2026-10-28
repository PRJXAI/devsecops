//! Native evidence only for one explicitly authorized Gitleaks dependency candidate.
//! No release receipts, scan exceptions, publisher input or generic rebuild interface.
use super::*;
use std::process::Command;
const COMPILER: &str =
    "golang:1.27.3@sha256:898838c455eecb68ed7b0b6f0635630ebdd657e732f07a23d0ab475007a52c36";
const SOURCE: &str =
    "https://codeload.github.com/gitleaks/gitleaks/tar.gz/83d9cd684c87d95d656c1458ef04895a7f1cbd8e";
const SOURCE_HASH: &str = "6b2638a733b85619dc80bdf28e84e4fed7e526a761ab5c148fbf67695aea2115";
const PATCH_HASH: &str = "25ffa10aef86ce506a4f66f8a294014de23031b96b27fa757be7b584f13af051";
const MOD_HASH: &str = "ba06359b7031ccdda2687fc4553291ffa7f1075b062f38a0bce4e51f7ff4d3c0";
const SUM_HASH: &str = "9f27b112986f235ee2b771bfa5c38e3dbf7521eac1e5722b42f5b528214b3b5c";
const TARGETS: [(&str, &str); 7] = [
    ("golang.org/x/crypto", "v0.58.0"),
    ("golang.org/x/text", "v0.43.0"),
    ("golang.org/x/sys", "v0.49.0"),
    ("github.com/klauspost/compress", "v1.20.3"),
    ("github.com/nwaples/rardecode/v2", "v2.4.5"),
    ("github.com/ulikunitz/xz", "v0.5.17"),
    ("golang.org/x/sync", "v0.24.0"),
];

fn captured_copy(output: &Path, target: &Path, expected: &str) -> Result<()> {
    if hash(output, 1024 * 1024)? != expected {
        return Err("candidate input hash mismatch");
    }
    write_new(target, &bytes(output, 1024 * 1024)?, 0o444)
}
fn compile(driver: &mut Driver, context: &Path, phase: &mut &'static str) -> Result<()> {
    *phase = "source-retrieval";
    let mut curl = Command::new("curl");
    curl.env_clear().args([
        "--disable",
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--connect-timeout",
        "15",
        "--max-time",
        "120",
        "--max-filesize",
        "1048576",
        SOURCE,
    ]);
    let archive = driver.execute(curl, 130, false, 0)?;
    captured_copy(&archive, &context.join("source.tar.gz"), SOURCE_HASH)?;
    let patch = driver
        .root
        .join("patches/gitleaks-8.30.1-dependencies.patch.txt");
    captured_copy(&patch, &context.join("dependencies.patch"), PATCH_HASH)?;
    *phase = "compiler-pull";
    driver.docker(&["pull", COMPILER], 300, false)?;
    let name = format!(
        "gitleaks-build-{}",
        driver
            .logs
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or("invalid private log name")?
    );
    let result = (|| {
        *phase = "compiler-container";
        driver.docker(
            &[
                "create",
                "--name",
                &name,
                "--network=bridge",
                "--read-only",
                "--user=65532:65532",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--cpus=4",
                "--memory=4g",
                "--memory-swap=4g",
                "--pids-limit=256",
                "--tmpfs",
                "/src:rw,exec,nosuid,nodev,size=256m,mode=1777",
                "--tmpfs",
                "/tmp:rw,exec,nosuid,nodev,size=3g,mode=1777",
                "--mount",
                &mount(&context.join("source.tar.gz"), "/input/source.tar.gz", true)?,
                "--mount",
                &mount(
                    &context.join("dependencies.patch"),
                    "/input/dependencies.patch",
                    true,
                )?,
                "--env",
                "HOME=/tmp",
                "--env",
                "GOTOOLCHAIN=local",
                "--env",
                "GOMODCACHE=/tmp/modcache",
                "--env",
                "GOCACHE=/tmp/buildcache",
                "--env",
                "GOPROXY=https://proxy.golang.org",
                "--env",
                "GOSUMDB=sum.golang.org",
                "--env",
                "GOMAXPROCS=4",
                "--env",
                "CGO_ENABLED=0",
                "--env",
                "GOFLAGS=-mod=readonly",
                "--env",
                "GIT_CONFIG_NOSYSTEM=1",
                "--env",
                "GIT_CONFIG_GLOBAL=/dev/null",
                "--entrypoint",
                "/bin/sleep",
                COMPILER,
                "1800",
            ],
            30,
            false,
        )?;
        driver.docker(&["start", &name], 30, false)?;
        driver.docker(
            &[
                "exec",
                "--workdir=/src",
                &name,
                "tar",
                "--no-same-owner",
                "-xzf",
                "/input/source.tar.gz",
                "--strip-components=1",
                "-C",
                "/src",
            ],
            30,
            false,
        )?;
        driver.docker(
            &[
                "exec",
                "--workdir=/src",
                &name,
                "git",
                "apply",
                "--check",
                "/input/dependencies.patch",
            ],
            30,
            false,
        )?;
        driver.docker(
            &[
                "exec",
                "--workdir=/src",
                &name,
                "git",
                "apply",
                "/input/dependencies.patch",
            ],
            30,
            false,
        )?;
        for (file, expected) in [("go.mod", MOD_HASH), ("go.sum", SUM_HASH)] {
            let output =
                driver.docker(&["exec", "--workdir=/src", &name, "cat", file], 15, false)?;
            if hash(&output, 1024 * 1024)? != expected {
                return Err("applied candidate manifest differs from reviewed input");
            }
        }
        *phase = "module-retrieval";
        driver.docker(
            &["exec", "--workdir=/src", &name, "go", "mod", "download"],
            600,
            false,
        )?;
        // Only this owned build container had network access; test/build are offline.
        driver.docker(&["network", "disconnect", "bridge", &name], 30, false)?;
        *phase = "offline-module-verification";
        driver.docker(
            &["exec", "--workdir=/src", &name, "go", "mod", "verify"],
            60,
            false,
        )?;
        *phase = "upstream-race-tests";
        driver.docker(
            &[
                "exec",
                "--workdir=/src",
                "--env=CGO_ENABLED=1",
                &name,
                "go",
                "test",
                "-mod=readonly",
                "-race",
                "./...",
            ],
            900,
            false,
        )?;
        *phase = "compile";
        driver.docker(
            &[
                "exec",
                "--workdir=/src",
                &name,
                "go",
                "build",
                "-mod=readonly",
                "-ldflags=-X=github.com/zricethezav/gitleaks/v8/version.Version=8.30.1",
                "-o",
                "/src/candidate",
                ".",
            ],
            300,
            false,
        )?;
        for (file, expected) in [("go.mod", MOD_HASH), ("go.sum", SUM_HASH)] {
            let output =
                driver.docker(&["exec", "--workdir=/src", &name, "cat", file], 15, false)?;
            if hash(&output, 1024 * 1024)? != expected {
                return Err("candidate build changed reviewed manifests");
            }
        }
        *phase = "artifact-transfer";
        // docker cp may not see the running container's tmpfs. Transfer bounded
        // chunks through the capped capture path, never widen the stream limit.
        let length = driver.docker(
            &["exec", &name, "stat", "-c", "%s", "/src/candidate"],
            15,
            false,
        )?;
        let length = std::str::from_utf8(&bytes(&length, 128)?)
            .map_err(|_| "invalid candidate length")?
            .trim()
            .parse::<usize>()
            .map_err(|_| "invalid candidate length")?;
        if length == 0 || length > 64 * 1024 * 1024 {
            return Err("candidate size exceeds transfer budget");
        }
        let source_hash =
            driver.docker(&["exec", &name, "sha256sum", "/src/candidate"], 15, false)?;
        let expected = bytes(&source_hash, 256)?;
        let expected = std::str::from_utf8(&expected)
            .map_err(|_| "invalid candidate digest")?
            .split_whitespace()
            .next()
            .filter(|v| hex(v, 64))
            .ok_or("invalid candidate digest")?;
        let target = context.join("candidate");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .map_err(|_| "cannot create candidate binary")?;
        const CHUNK: usize = 4 * 1024 * 1024;
        for index in 0..length.div_ceil(CHUNK) {
            let chunk = driver.docker(
                &[
                    "exec",
                    &name,
                    "dd",
                    "if=/src/candidate",
                    "bs=4194304",
                    "count=1",
                    &format!("skip={index}"),
                    "status=none",
                ],
                60,
                false,
            )?;
            let data = bytes(&chunk, CHUNK as u64)?;
            if data.len() != (length - index * CHUNK).min(CHUNK) {
                return Err("candidate transfer length mismatch");
            }
            file.write_all(&data)
                .map_err(|_| "cannot retain candidate chunk")?;
        }
        file.sync_all()
            .map_err(|_| "cannot sync candidate binary")?;
        if hash(&target, 64 * 1024 * 1024)? != expected {
            return Err("candidate transfer digest mismatch");
        }
        Ok(source_hash)
    })();
    let cleanup = driver.docker(&["rm", "--force", &name], 15, true);
    super::super::container_output(result, cleanup).map(|_| ())
}
fn validate(driver: &mut Driver, public: &Path, phase: &mut &'static str) -> Result<Value> {
    *phase = "native-endpoint";
    let (arch, endpoint) = driver.native()?;
    let revision = std::env::var("GITHUB_SHA").unwrap_or_else(|_| "local".into());
    if revision != "local" {
        sha(&revision)?;
    }
    let context = driver.logs.join("gitleaks-context");
    mkdir(&context, false)?;
    write_new(
        &context.join("Dockerfile"),
        include_bytes!("../tests/fixtures/gitleaks/Dockerfile"),
        0o600,
    )?;
    write_new(
        &context.join(".dockerignore"),
        b"*\n!Dockerfile\n!candidate\n",
        0o600,
    )?;
    compile(driver, &context, phase)?;
    *phase = "candidate-image";
    let iid = driver.logs.join("gitleaks-candidate.iid");
    let mut build = Command::new("docker");
    build
        .env_remove("DOCKER_CONTEXT")
        .current_dir(&context)
        .args([
            "--host",
            &endpoint,
            "buildx",
            "build",
            "--builder",
            "default",
            "--load",
            "--platform",
            &format!("linux/{arch}"),
            "--label",
            "org.opencontainers.image.source=https://github.com/PRJXAI/devsecops",
            "--label",
            &format!("org.opencontainers.image.revision={revision}"),
            "--iidfile",
        ])
        .arg(&iid)
        .arg(".");
    driver.execute(build, 600, false, 0)?;
    let image = super::super::built_image_id(&iid)?;
    driver.inspect(&image, arch)?;
    *phase = "version-smokes";
    driver.smoke(&image, "gitleaks", &["version"], None)?;
    driver.smoke(&image, "gitleaks", &["--version"], Some("/usr/bin/git"))?;
    *phase = "filesystem-functional-contract";
    super::super::contracts::check(driver, "gitleaks", &image)?;
    *phase = "native-inventory";
    let tar = driver.logs.join("gitleaks-candidate.tar");
    driver.docker(
        &[
            "image",
            "save",
            "--output",
            tar.to_str().ok_or("invalid candidate archive path")?,
            &image,
        ],
        300,
        false,
    )?;
    regular(&tar, TAR_LIMIT)?;
    fs::set_permissions(&tar, fs::Permissions::from_mode(0o444))
        .map_err(|_| "cannot share public candidate archive")?;
    let config = super::super::archive::config_digest(&tar, arch, &revision)?;
    driver.docker(&["pull", SYFT], 300, false)?;
    let output = scanner(
        driver,
        SYFT,
        &["docker-archive:/input/image.tar", "-o", "syft-json"],
        &[mount(&tar, "/input/image.tar", true)?],
        false,
        0,
    )?;
    let bom = read_json(&output)?;
    sbom_packages(&bom, &config, arch)?;
    let mut modules = BTreeMap::new();
    for item in bom["artifacts"]
        .as_array()
        .ok_or("missing candidate inventory")?
    {
        if item["type"] == "go-module" {
            if text(item, "/metadata/goCompiledVersion")? != "go1.27.3" {
                return Err("unexpected candidate compiler");
            }
            let name = text(item, "/name")?;
            if modules.insert(name, text(item, "/version")?).is_some() {
                return Err("duplicate candidate module");
            }
        }
    }
    if modules.get("stdlib") != Some(&"go1.27.3")
        || modules.get("github.com/zricethezav/gitleaks/v8") != Some(&"v8.30.1")
    {
        return Err("missing candidate main/runtime inventory");
    }
    for (name, version) in TARGETS {
        if modules.get(name) != Some(&version) {
            return Err("missing exact upgraded candidate module");
        }
    }
    write_new(
        &public.join("gitleaks.syft.json"),
        &bytes(&output, JSON_LIMIT)?,
        0o600,
    )?;
    Ok(
        json!({"schema":1,"status":"functional-inventory-evidence-only","source_sha":revision,"arch":arch,"engine_image":image,"config_image":config,"compiler":COMPILER,"source_archive_sha256":SOURCE_HASH,"patch_sha256":PATCH_HASH,"go_mod_sha256":MOD_HASH,"go_sum_sha256":SUM_HASH,"upstream_race_tests":"passed","filesystem_functional_contract":"passed","sbom_sha256":hash(&output,JSON_LIMIT)?,"archive_sha256":hash(&tar,TAR_LIMIT)?,"vulnerability_scan":"not-run","release_accepted":false}),
    )
}
#[test]
fn candidate_inputs_are_hash_bound_create_only_and_nofollow() {
    let driver = Driver::new().unwrap();
    let source = driver.logs.join("input");
    let target = driver.logs.join("copy");
    write_new(&source, b"synthetic public fixture", 0o600).unwrap();
    assert!(captured_copy(&source, &target, &"0".repeat(64)).is_err());
    assert!(!target.exists());
    let expected = hash(&source, 1024).unwrap();
    captured_copy(&source, &target, &expected).unwrap();
    assert_eq!(bytes(&target, 1024).unwrap(), b"synthetic public fixture");
    assert!(captured_copy(&source, &target, &expected).is_err());
    let link = driver.logs.join("link");
    std::os::unix::fs::symlink(&source, &link).unwrap();
    assert!(captured_copy(&link, &driver.logs.join("another"), &expected).is_err());
}
#[test]
#[ignore = "authorized native local Docker; public fixed source/patch only, no scans/publication"]
fn native_gitleaks_dependency_candidate() {
    let mut driver = Driver::new().expect("candidate driver setup failed");
    let public = driver.root.join(".work/gitleaks-native-candidate");
    mkdir(&public, false).expect("refusing stale candidate evidence");
    write_json(
        &public.join("summary.json"),
        &json!({"schema":1,"status":"error","stage":"startup","release_accepted":false}),
    )
    .unwrap();
    let mut phase = "startup";
    let result = validate(&mut driver, &public, &mut phase);
    let status=result.as_ref().cloned().unwrap_or_else(|_|json!({"schema":1,"status":"error","stage":phase,"reason":"candidate-validation-failed","release_accepted":false}));
    write_json(&public.join("summary.next.json"), &status).unwrap();
    fs::rename(
        public.join("summary.next.json"),
        public.join("summary.json"),
    )
    .unwrap();
    assert!(
        result.is_ok(),
        "native candidate validation failed at {phase}; private logs retained"
    );
}
