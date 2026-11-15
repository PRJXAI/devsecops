//! Fixed-source Gitleaks production builder and historical candidate evidence test.
//! No caller-selected inputs, release approvals or generic rebuild interface.
use super::*;
use std::process::Command;
const COMPILER: &str =
    "golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d";
const SOURCE: &str =
    "https://codeload.github.com/gitleaks/gitleaks/tar.gz/83d9cd684c87d95d656c1458ef04895a7f1cbd8e";
const SOURCE_HASH: &str = "6b2638a733b85619dc80bdf28e84e4fed7e526a761ab5c148fbf67695aea2115";
const PATCH_HASH: &str = "cc22bde80f503fe26ab5075ff10c428feb83e320ecb19087042d409c25bbc21e";
const MOD_HASH: &str = "8b36b554e8ba97785c41ca2f261c30c8f08d6db50458039365c48e752305a3be";
const SUM_HASH: &str = "0b201de828353230fa0898c772260f926d13c5721b8997e44f490212cc53caf5";
const BROTLI_TEST_PATCH: &str = "fd0b039a32bc65392ca6c0c884311a05b055024836edc44908c2edf76573664a";
const BROTLI_ORIGINAL_TEST: &str =
    "c49806c65764d5d7f6fbf441e0e7c80f86a7fca4a3d7b823fdc6c1fd9f27572a";
const BROTLI_FIXED_TEST: &str = "a49f549fac39fc90e82e2d40ba5cf8402be68e6ee0fb33fde3c9521dc4f68fc2";
#[cfg(test)]
const TARGETS: [(&str, &str); 8] = [
    ("github.com/andybalholm/brotli", "v1.3.0"),
    ("golang.org/x/crypto", "v0.59.0"),
    ("golang.org/x/text", "v0.44.0"),
    ("golang.org/x/sys", "v0.50.0"),
    ("github.com/klauspost/compress", "v1.20.3"),
    ("github.com/nwaples/rardecode/v2", "v2.4.5"),
    ("github.com/ulikunitz/xz", "v0.5.17"),
    ("golang.org/x/sync", "v0.25.0"),
];

#[test]
fn brotli_fixture_patch_retains_all_assertions_and_never_changes_runtime_sources() {
    let patch = include_str!("../patches/brotli-1.3.0-streaming-test.patch.txt");
    let digest = <sha2::Sha256 as sha2::Digest>::digest(patch.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(digest, BROTLI_TEST_PATCH);
    assert_eq!(
        patch
            .lines()
            .filter(|line| line.starts_with("+++ "))
            .collect::<Vec<_>>(),
        ["+++ b/brotli_test.go"]
    );
    assert_eq!(
        patch
            .lines()
            .filter(|line| line.starts_with('-') && !line.starts_with("---"))
            .collect::<Vec<_>>(),
        ["-\terrch := make(chan error)", "-\tdefer close(ch)"]
    );
    assert!(patch.contains("+\t\t<-done"));
    assert!(patch.contains("+\t\tdefer close(done)"));
    assert!(!patch.contains("t.Skip"));
}

fn captured_copy(output: &Path, target: &Path, expected: &str) -> Result<()> {
    if hash(output, 1024 * 1024)? != expected {
        return Err("candidate input hash mismatch");
    }
    write_new(target, &bytes(output, 1024 * 1024)?, 0o444)
}
/// Assemble only the hash-bound collected texts, preserving every original byte.
/// This is packaging, not a completeness or redistribution approval assertion.
pub(crate) fn go_notices(root: &Path) -> Result<Vec<u8>> {
    let folder = root.join("licenses/gitleaks-go-notices");
    let index = folder.join("index.json");
    if hash(&index, 1024 * 1024)?
        != "07a6e2d84057faea19bfd39ebad5fdd94523ab464f7237a28f6ed76fe0765e0c"
    {
        return Err("Gitleaks notice index differs from reviewed collection");
    }
    let index = read_json(&index)?;
    if index["compiler"] != "go1.27.4"
        || index["native_modules"] != 63
        || hash(&folder.join("current-source-index.json"), 1024 * 1024)?
            != text(&index, "/module_source_index_sha256")?
    {
        return Err("Gitleaks native legal source index differs");
    }
    let mut bundle =
        b"Collected Gitleaks/Go notices. Native runtime/source review remains separate.\n".to_vec();
    for record in index["files"].as_array().ok_or("missing notice files")? {
        let name = text(record, "/file")?;
        if !name.starts_with("files/") || name.contains("..") || name.matches('/').count() != 1 {
            return Err("invalid notice file path");
        }
        let path = folder.join(name);
        if hash(&path, 1024 * 1024)? != text(record, "/sha256")? {
            return Err("Gitleaks notice bytes differ from reviewed collection");
        }
        let data = bytes(&path, 1024 * 1024)?;
        if record["bytes"].as_u64() != Some(data.len() as u64) {
            return Err("Gitleaks notice size differs from reviewed collection");
        }
        bundle
            .extend_from_slice(format!("\n--- {} ---\n", text(record, "/source_path")?).as_bytes());
        bundle.extend_from_slice(&data);
        if bundle.len() > 1024 * 1024 {
            return Err("Gitleaks notice bundle exceeds budget");
        }
    }
    Ok(bundle)
}

pub(crate) fn build_context(driver: &mut Driver) -> Result<PathBuf> {
    let context = driver
        .logs
        .join(format!("gitleaks-production-context-{}", driver.sequence));
    mkdir(&context, false)?;
    write_new(
        &context.join("Dockerfile"),
        include_bytes!("../images/gitleaks/Dockerfile"),
        0o600,
    )?;
    write_new(
        &context.join(".dockerignore"),
        b"*\n!Dockerfile\n!candidate\n!go-notices.txt\n!native-notices.txt\n!source-index.json\n!sources/\n!sources/*.apk\n",
        0o600,
    )?;
    write_new(
        &context.join("go-notices.txt"),
        &go_notices(&driver.root)?,
        0o444,
    )?;
    let mut phase = "startup";
    let result = compile(driver, &context, &mut phase);
    write_json(
        &driver.logs.join("gitleaks-production-build.json"),
        &json!({
            "status":if result.is_ok() {"built"} else {"error"}, "stage":phase,
            "compiler":COMPILER, "source_archive_sha256":SOURCE_HASH,
            "patch_sha256":PATCH_HASH, "go_mod_sha256":MOD_HASH, "go_sum_sha256":SUM_HASH
        }),
    )?;
    result?;
    super::gitleaks_runtime::install(driver, &context)?;
    Ok(context)
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
    captured_copy(
        &driver
            .root
            .join("patches/brotli-1.3.0-streaming-test.patch.txt"),
        &context.join("brotli-test.patch"),
        BROTLI_TEST_PATCH,
    )?;
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
                "--mount",
                &mount(
                    &context.join("brotli-test.patch"),
                    "/input/brotli-test.patch",
                    true,
                )?,
                "--env",
                "HOME=/tmp",
                "--env",
                "GOTOOLCHAIN=local",
                "--env",
                "GOPATH=/tmp/go",
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
        // Explicit upstream test prerequisite already checksum-bound in go.sum;
        // downloading an unrelated pruned module graph would mutate that lock.
        driver.docker(
            &[
                "exec",
                "--workdir=/src",
                &name,
                "go",
                "mod",
                "download",
                "github.com/xyproto/randomstring@v1.0.5",
            ],
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
                "--env=GOPROXY=off",
                &name,
                "go",
                "test",
                "-mod=readonly",
                "-race",
                "-count=1",
                "./...",
            ],
            900,
            false,
        )?;
        *phase = "brotli-upstream-fixture-control";
        // Never alter the checksum-verified module cache or shipped dependency.
        // This copied upstream TEST alone needs synchronization before Close.
        let brotli = "/src/brotli-unit";
        driver.docker(
            &[
                "exec",
                &name,
                "cp",
                "-R",
                "/tmp/modcache/github.com/andybalholm/brotli@v1.3.0",
                brotli,
            ],
            30,
            false,
        )?;
        driver.docker(&["exec", &name, "chmod", "-R", "u+w", brotli], 30, false)?;
        let original = driver.docker(
            &[
                "exec",
                &name,
                "sha256sum",
                "/src/brotli-unit/brotli_test.go",
            ],
            15,
            false,
        )?;
        if !bytes(&original, 256)?.starts_with(BROTLI_ORIGINAL_TEST.as_bytes()) {
            return Err("changed upstream Brotli fixture");
        }
        let mut negative = Command::new("docker");
        negative.args([
            "exec",
            "--workdir=/src/brotli-unit",
            "--env=CGO_ENABLED=1",
            "--env=GOPROXY=off",
            &name,
            "go",
            "test",
            "-race",
            "-count=1",
            "-run=^TestDecoderStreaming$",
            ".",
        ]);
        let evidence = driver.execute(negative, 900, false, 1)?;
        let evidence = bytes(&evidence, crate::LOG_LIMIT as u64)?;
        if !evidence
            .windows(b"WARNING: DATA RACE".len())
            .any(|w| w == b"WARNING: DATA RACE")
            || !evidence
                .windows(b"FAIL: TestDecoderStreaming".len())
                .any(|w| w == b"FAIL: TestDecoderStreaming")
        {
            return Err("Brotli negative control did not reproduce the fixture race");
        }
        *phase = "brotli-upstream-unit-races";
        driver.docker(
            &[
                "exec",
                "--workdir=/src/brotli-unit",
                &name,
                "git",
                "apply",
                "--check",
                "/input/brotli-test.patch",
            ],
            30,
            false,
        )?;
        driver.docker(
            &[
                "exec",
                "--workdir=/src/brotli-unit",
                &name,
                "git",
                "apply",
                "/input/brotli-test.patch",
            ],
            30,
            false,
        )?;
        let fixed = driver.docker(
            &[
                "exec",
                &name,
                "sha256sum",
                "/src/brotli-unit/brotli_test.go",
            ],
            15,
            false,
        )?;
        if !bytes(&fixed, 256)?.starts_with(BROTLI_FIXED_TEST.as_bytes()) {
            return Err("changed synchronized Brotli fixture");
        }
        driver.docker(
            &[
                "exec",
                "--workdir=/src/brotli-unit",
                "--env=CGO_ENABLED=1",
                "--env=GOPROXY=off",
                &name,
                "go",
                "test",
                "-race",
                "-count=1",
                "./...",
            ],
            900,
            false,
        )?;
        // Original runtime module bytes must still verify after fixture tests.
        driver.docker(
            &["exec", "--workdir=/src", &name, "go", "mod", "verify"],
            60,
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
#[cfg(test)]
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
        // Qualify the current fixed derivative; old fixture/recorded evidence
        // remains historical and is never rebound as current approval.
        include_bytes!("../images/gitleaks/Dockerfile"),
        0o600,
    )?;
    write_new(
        &context.join(".dockerignore"),
        b"*\n!Dockerfile\n!candidate\n!go-notices.txt\n!native-notices.txt\n!source-index.json\n!sources/\n!sources/*.apk\n",
        0o600,
    )?;
    write_new(
        &context.join("go-notices.txt"),
        &go_notices(&driver.root)?,
        0o444,
    )?;
    compile(driver, &context, phase)?;
    *phase = "corresponding-source-delivery";
    super::gitleaks_runtime::install(driver, &context)?;
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
    driver.docker_archive(&["image", "save", &image], &tar)?;
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
            if text(item, "/metadata/goCompiledVersion")? != "go1.27.4" {
                return Err("unexpected candidate compiler");
            }
            let name = text(item, "/name")?;
            if modules.insert(name, text(item, "/version")?).is_some() {
                return Err("duplicate candidate module");
            }
        }
    }
    if modules.get("stdlib") != Some(&"go1.27.4")
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
#[cfg(test)]
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
#[cfg(test)]
#[test]
fn production_notices_preserve_all_texts_and_reject_missing_changed_or_linked_inputs() {
    let driver = Driver::new().unwrap();
    let good = go_notices(&driver.root).unwrap();
    let index = read_json(&driver.root.join("licenses/gitleaks-go-notices/index.json")).unwrap();
    assert!(good.len() > 294214 && good.len() < 1024 * 1024);
    let root = driver.logs.join("notice-fixture");
    let folder = root.join("licenses/gitleaks-go-notices");
    fs::create_dir_all(folder.join("files")).unwrap();
    assert!(go_notices(&root).is_err());
    for name in ["index.json", "current-source-index.json"]
        .into_iter()
        .chain(
            index["files"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["file"].as_str().unwrap()),
        )
    {
        let data = bytes(
            &driver.root.join("licenses/gitleaks-go-notices").join(name),
            1024 * 1024,
        )
        .unwrap();
        write_new(&folder.join(name), &data, 0o600).unwrap();
        if name.starts_with("files/") {
            assert!(good.windows(data.len()).any(|chunk| chunk == data));
        }
    }
    assert_eq!(go_notices(&root).unwrap(), good);
    let target = folder.join(index["files"][0]["file"].as_str().unwrap());
    let original = bytes(&target, 1024 * 1024).unwrap();
    fs::remove_file(&target).unwrap();
    assert!(go_notices(&root).is_err());
    write_new(&target, b"changed", 0o600).unwrap();
    assert!(go_notices(&root).is_err());
    fs::remove_file(&target).unwrap();
    let outside = driver.logs.join("notice-original");
    write_new(&outside, &original, 0o600).unwrap();
    std::os::unix::fs::symlink(&outside, &target).unwrap();
    assert!(go_notices(&root).is_err());
    fs::remove_file(&target).unwrap();
    write_new(&target, &original, 0o600).unwrap();
    let source_index = folder.join("current-source-index.json");
    let source_bytes = bytes(&source_index, 1024 * 1024).unwrap();
    fs::remove_file(&source_index).unwrap();
    assert!(go_notices(&root).is_err());
    write_new(&source_index, b"changed", 0o600).unwrap();
    assert!(go_notices(&root).is_err());
    fs::remove_file(&source_index).unwrap();
    write_new(&source_index, &source_bytes, 0o600).unwrap();
    assert_eq!(go_notices(&root).unwrap(), good);
    fs::write(folder.join("index.json"), b"{}").unwrap();
    assert!(go_notices(&root).is_err());
}

#[cfg(test)]
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
