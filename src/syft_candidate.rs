//! Fixed-source Syft compiler measurement. Test-only; no production handoff or override.
use super::*;
use std::process::Command;

#[path = "syft_dependencies.rs"]
mod dependencies;
#[path = "syft_recorded.rs"]
mod recorded;
use dependencies::resolve_dependencies;

const SOURCE: &str =
    "https://codeload.github.com/anchore/syft/tar.gz/f15c3343e29dfb20cf6d82c820e7090b49808c96";
const SOURCE_HASH: &str = "a0547379caa1bd54f998134be5331e05b249b881265642467b37e0052cf8a890";
const MOD_HASH: &str = "a9e851acedee1cdcba947101a44d6fd4182dbd947fc26d9565216eb397966419";
const SUM_HASH: &str = "ccc0ebd03e9063d4aaf162f8c9c38a1a17dff103a545de691954e0d08a02870f";
const PATCH_HASH: &str = "32a07406444bab7a0d66f123a608a2b3532e540c3813d9383ae335813afecbb2";
const PATCHED_MOD: &str = "b0f6e276ba0c85de61332c1d8d2384aef2879c390a1be816b64792851bfc1300";
const PATCHED_SUM: &str = "c728864ef1965d35ba9554fa3390ff1e1cd7d51f59419a1fb0cc8f5c2a03cc60";
const COMPILER: &str =
    "golang:1.27.3@sha256:898838c455eecb68ed7b0b6f0635630ebdd657e732f07a23d0ab475007a52c36";
const TAGS: &str = "-tags=containers_image_openpgp,exclude_graphdriver_btrfs";
const FIXTURE: &str = "9df921c1b16830077fb36f9f915bfe6052875dfb966979a384bd90e91020ddf8";

fn copy_fixed(input: &Path, output: &Path, expected: &str) -> Result<()> {
    if hash(input, 8 * 1024 * 1024)? != expected {
        return Err("Syft candidate input hash mismatch");
    }
    write_new(output, &bytes(input, 8 * 1024 * 1024)?, 0o444)
}
fn manifests(driver: &mut Driver, name: &str, work: Work) -> Result<()> {
    for (file, expected) in if matches!(work, Work::Patched) {
        [("go.mod", PATCHED_MOD), ("go.sum", PATCHED_SUM)]
    } else {
        [("go.mod", MOD_HASH), ("go.sum", SUM_HASH)]
    } {
        let output = driver.docker(&["exec", "--workdir=/src", name, "cat", file], 30, false)?;
        if hash(&output, 1024 * 1024)? != expected {
            return Err("Syft candidate changed original manifests");
        }
    }
    Ok(())
}
fn transfer(driver: &mut Driver, name: &str, context: &Path) -> Result<PathBuf> {
    let length = driver.docker(
        &["exec", name, "stat", "-c", "%s", "/src/candidate"],
        30,
        false,
    )?;
    let length = std::str::from_utf8(&bytes(&length, 128)?)
        .map_err(|_| "invalid Syft binary size")?
        .trim()
        .parse::<usize>()
        .map_err(|_| "invalid Syft binary size")?;
    if length == 0 || length > 128 * 1024 * 1024 {
        return Err("Syft binary exceeds transfer budget");
    }
    let digest = driver.docker(&["exec", name, "sha256sum", "/src/candidate"], 30, false)?;
    let expected = bytes(&digest, 256)?;
    let expected = std::str::from_utf8(&expected)
        .map_err(|_| "invalid Syft binary digest")?
        .split_whitespace()
        .next()
        .filter(|v| hex(v, 64))
        .ok_or("invalid Syft binary digest")?;
    let target = context.join("candidate");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&target)
        .map_err(|_| "cannot create Syft binary")?;
    const CHUNK: usize = 4 * 1024 * 1024;
    for index in 0..length.div_ceil(CHUNK) {
        let part = driver.docker(
            &[
                "exec",
                name,
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
        let data = bytes(&part, CHUNK as u64)?;
        if data.len() != (length - index * CHUNK).min(CHUNK) {
            return Err("Syft transfer length mismatch");
        }
        file.write_all(&data)
            .map_err(|_| "cannot retain Syft binary")?;
    }
    file.sync_all().map_err(|_| "cannot sync Syft binary")?;
    if hash(&target, 128 * 1024 * 1024)? != expected {
        return Err("Syft transfer digest mismatch");
    }
    Ok(digest)
}
#[derive(Clone, Copy)]
enum Work {
    Compile,
    ResolveDependencies,
    Patched,
}
fn compile(
    driver: &mut Driver,
    context: &Path,
    phase: &mut &'static str,
    work: Work,
) -> Result<bool> {
    *phase = "source-retrieval";
    let mut fetch = Command::new("curl");
    fetch.env_clear().args([
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
        "8388608",
        SOURCE,
    ]);
    let source = driver.execute(fetch, 130, false, 0)?;
    copy_fixed(&source, &context.join("source.tar.gz"), SOURCE_HASH)?;
    copy_fixed(
        &driver
            .root
            .join("patches/syft-1.55.0-dependencies.patch.txt"),
        &context.join("fixed.patch"),
        PATCH_HASH,
    )?;
    *phase = "compiler-pull";
    driver.docker(&["pull", COMPILER], 300, false)?;
    let name = format!(
        "syft-build-{}",
        driver
            .logs
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or("invalid run identity")?
    );
    let mut tests_passed = false;
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
                "--memory=8g",
                "--memory-swap=8g",
                "--pids-limit=256",
                "--tmpfs",
                "/src:rw,exec,nosuid,nodev,size=512m,mode=1777",
                "--tmpfs",
                "/tmp:rw,exec,nosuid,nodev,size=6g,mode=1777",
                "--mount",
                &mount(&context.join("source.tar.gz"), "/input/source.tar.gz", true)?,
                "--mount",
                &mount(
                    &context.join("fixed.patch"),
                    "/input/dependencies.patch",
                    true,
                )?,
                "--env",
                "HOME=/tmp",
                "--env",
                "GOPATH=/tmp/go",
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
                "2400",
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
        manifests(driver, &name, Work::Compile)?;
        if matches!(work, Work::ResolveDependencies) {
            *phase = "dependency-resolution-only";
            return resolve_dependencies(driver, &name, context);
        }
        if matches!(work, Work::Patched) {
            *phase = "apply-fixed-dependencies";
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
            manifests(driver, &name, work)?;
        }
        *phase = "module-retrieval";
        driver.docker(
            &["exec", "--workdir=/src", &name, "go", "mod", "download"],
            600,
            false,
        )?;
        driver.docker(&["network", "disconnect", "bridge", &name], 30, false)?;
        *phase = "offline-module-verification";
        driver.docker(
            &["exec", "--workdir=/src", &name, "go", "mod", "verify"],
            60,
            false,
        )?;
        manifests(driver, &name, work)?;
        let graph = driver.docker(
            &["exec", "--workdir=/src", &name, "go", "mod", "graph"],
            60,
            false,
        )?;
        write_new(
            &context.join("module-graph.txt"),
            &bytes(&graph, 8 * 1024 * 1024)?,
            0o600,
        )?;
        *phase = "compile";
        driver.docker(&["exec","--workdir=/src",&name,"go","build",TAGS,"-ldflags=-w -s -extldflags '-static' -X main.version=1.55.0 -X main.gitCommit=f15c3343e29dfb20cf6d82c820e7090b49808c96 -X main.buildDate=unknown -X main.gitDescription=v1.55.0-compiler-evaluation","-o","/src/candidate","./cmd/syft"],600,false)?;
        manifests(driver, &name, work)?;
        let metadata = driver.docker(
            &["exec", &name, "go", "version", "-m", "/src/candidate"],
            30,
            false,
        )?;
        write_new(
            &context.join("binary-metadata.txt"),
            &bytes(&metadata, 1024 * 1024)?,
            0o600,
        )?;
        let imports = driver.docker(
            &[
                "exec",
                "--workdir=/src",
                &name,
                "go",
                "list",
                TAGS,
                "-deps",
                "-f",
                "{{.ImportPath}}",
                "./cmd/syft",
            ],
            60,
            false,
        )?;
        write_new(
            &context.join("imports.txt"),
            &bytes(&imports, 1024 * 1024)?,
            0o600,
        )?;
        let transferred = transfer(driver, &name, context)?;
        *phase = "upstream-race-tests";
        // Release only this owned compiler's normal build cache, not modules or
        // evidence, before the full race suite; keep the original byte budget.
        driver.docker(&["exec", &name, "go", "clean", "-cache"], 30, false)?;
        // The executable was already transferred. Any test failure remains a
        // qualification failure; cleanup kills all owned work before measurement.
        tests_passed = driver
            .docker(
                &[
                    "exec",
                    "--workdir=/src",
                    "--env=CGO_ENABLED=1",
                    &name,
                    "go",
                    "test",
                    "-race",
                    "-p=1",
                    TAGS,
                    "./...",
                ],
                900,
                false,
            )
            .is_ok();
        if tests_passed {
            manifests(driver, &name, work)?;
        }
        Ok(transferred)
    })();
    let cleanup = driver.docker(&["rm", "--force", &name], 15, true);
    crate::container_output(result, cleanup)?;
    if driver.cancelled.load(Ordering::Relaxed) {
        return Err("Syft candidate cancelled");
    }
    Ok(tests_passed)
}

fn modules(catalog: &Value, compiler: &str) -> Result<BTreeMap<String, String>> {
    let mut modules = BTreeMap::new();
    for item in catalog["artifacts"]
        .as_array()
        .ok_or("missing Syft module inventory")?
    {
        if item["type"] == "go-module" {
            if text(item, "/metadata/goCompiledVersion")? != compiler {
                return Err("Syft compiler inventory drift");
            }
            let name = text(item, "/name")?.to_owned();
            if modules
                .insert(name, text(item, "/version")?.to_owned())
                .is_some()
            {
                return Err("duplicate Syft module inventory");
            }
        }
    }
    if !modules.contains_key("github.com/anchore/syft")
        || modules.get("stdlib").map(String::as_str) != Some(compiler)
    {
        return Err("Syft payload/runtime inventory missing");
    }
    Ok(modules)
}
fn observe(
    driver: &mut Driver,
    image: &str,
    arch: &str,
    label: &str,
    public: &Path,
    cache: &Path,
    db: &Value,
) -> Result<(Value, Value)> {
    let archive = driver.logs.join(format!("{label}.tar"));
    driver.docker_archive(&["image", "save", image], &archive)?;
    let (config, data, _) = crate::archive::saved_config(&archive)?;
    let identity: Value =
        serde_json::from_slice(&data).map_err(|_| "invalid candidate saved config")?;
    if identity["architecture"] != arch || identity["os"] != "linux" {
        return Err("wrong candidate platform");
    }
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o444))
        .map_err(|_| "cannot expose candidate archive")?;
    let output = scanner(
        driver,
        SYFT,
        &["docker-archive:/input/image.tar", "-o", "syft-json"],
        &[mount(&archive, "/input/image.tar", true)?],
        false,
        0,
    )?;
    let catalog = read_json(&output)?;
    let packages = sbom_packages(&catalog, &config, arch)?;
    let staged = driver.logs.join(format!("{label}.syft.json"));
    write_new(&staged, &bytes(&output, JSON_LIMIT)?, 0o444)?;
    let report = scanner(
        driver,
        GRYPE,
        &["sbom:/input/syft.json", "--output", "json"],
        &[
            mount(&staged, "/input/syft.json", true)?,
            mount(cache, "/cache", true)?,
        ],
        false,
        0,
    )?;
    let raw = read_json(&report)?;
    let counts = report_counts(&catalog, &packages, &raw, db, Utc::now())?;
    let decision = risk::assess("syft", &catalog, &raw)?;
    // Only counts and immutable identities are public, never raw matches/logs.
    let result = json!({"engine_image":image,"config_image":config,"archive_sha256":hash(&archive,TAR_LIMIT)?,"sbom_sha256":hash(&staged,JSON_LIMIT)?,"report_sha256":hash(&report,JSON_LIMIT)?,"counts":counts,"risk":decision,"diagnostics":risk::diagnostics(&crate::captured_stderr(&report)?)?});
    write_json(&public.join(format!("{label}.json")), &result)?;
    Ok((catalog, result))
}
fn evaluate(
    driver: &mut Driver,
    public: &Path,
    phase: &mut &'static str,
    work: Work,
) -> Result<Value> {
    let (arch, endpoint) = driver.native()?;
    let context = driver.logs.join("syft-context");
    mkdir(&context, false)?;
    copy_fixed(
        &driver.root.join("tests/fixtures/syft-compiler/Dockerfile"),
        &context.join("Dockerfile"),
        FIXTURE,
    )?;
    write_new(
        &context.join(".dockerignore"),
        b"*\n!Dockerfile\n!candidate\n",
        0o600,
    )?;
    let tests_passed = compile(driver, &context, phase, work)?;
    write_json(
        &public.join("build.json"),
        &json!({"schema":1,"source_archive_sha256":SOURCE_HASH,"compiler":COMPILER,"upstream_race_tests":if tests_passed {"passed"} else {"failed"},"candidate_binary_sha256":hash(&context.join("candidate"),128 * 1024 * 1024)?,"release_accepted":false}),
    )?;
    *phase = "candidate-image";
    let iid = driver.logs.join("syft-candidate.iid");
    let mut build = Command::new("docker");
    build
        .env_remove("DOCKER_CONTEXT")
        .env_remove("BUILDX_BUILDER")
        .env_remove("BUILDKIT_HOST")
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
            "org.opencontainers.image.revision=local",
            "--iidfile",
        ])
        .arg(&iid)
        .arg(".");
    driver.execute(build, 600, false, 0)?;
    let image = crate::built_image_id(&iid)?;
    driver.inspect(&image, arch)?;
    *phase = "filesystem-functional-contract";
    driver.smoke(&image, "syft", &["version"], None)?;
    crate::contracts::check(driver, "syft", &image)?;
    *phase = "fresh-analysis-engines-db";
    for engine in [SYFT, GRYPE] {
        driver.docker(&["pull", engine], 300, false)?;
    }
    let cache = public.join("cache");
    mkdir(&cache, true)?;
    scanner(
        driver,
        GRYPE,
        &["db", "update"],
        &[mount(&cache, "/cache", false)?],
        true,
        0,
    )?;
    let status = scanner(
        driver,
        GRYPE,
        &["db", "status", "--output", "json"],
        &[mount(&cache, "/cache", true)?],
        false,
        0,
    )?;
    let db = read_json(&status)?;
    db_status(&db, Utc::now())?;
    *phase = "candidate-catalog-scan";
    let (candidate, measured) = observe(driver, &image, arch, "candidate", public, &cache, &db)?;
    let candidate_modules = modules(&candidate, "go1.27.3")?;
    if matches!(work, Work::Patched)
        && (candidate_modules
            .get("github.com/go-jose/go-jose/v4")
            .map(String::as_str)
            != Some("v4.1.6")
            || candidate_modules
                .get("golang.org/x/net")
                .map(String::as_str)
                != Some("v0.62.0"))
    {
        return Err("upgraded Syft binary omits dependency targets");
    }
    *phase = "supplier-comparison";
    let original = driver.check("syft")?;
    let (baseline, previous) = observe(driver, &original, arch, "supplier", public, &cache, &db)?;
    let baseline_modules = modules(&baseline, "go1.26.8")?;
    let added: Vec<_> = candidate_modules
        .keys()
        .filter(|n| !baseline_modules.contains_key(*n))
        .collect();
    let removed: Vec<_> = baseline_modules
        .keys()
        .filter(|n| !candidate_modules.contains_key(*n))
        .collect();
    let changed: Vec<_> = candidate_modules
        .iter()
        .filter(|(n, v)| baseline_modules.get(*n).is_some_and(|old| old != *v))
        .map(|(n, v)| json!({"module":n,"before":baseline_modules[n],"after":v}))
        .collect();
    let mut result = json!({"schema":1,"status":"measurement-not-release","created":Utc::now().to_rfc3339(),"arch":arch,"compiler":COMPILER,"source_archive_sha256":SOURCE_HASH,"go_mod_sha256":if matches!(work,Work::Patched) {PATCHED_MOD} else {MOD_HASH},"go_sum_sha256":if matches!(work,Work::Patched) {PATCHED_SUM} else {SUM_HASH},"dependency_patch_sha256":if matches!(work,Work::Patched) {Some(PATCH_HASH)} else {None},"fixture_sha256":FIXTURE,"upstream_race_tests":if tests_passed {"passed"} else {"failed"},"filesystem_functional_contract":"passed","candidate":measured,"supplier":previous,"compiler_input":{"status":"not-completed"},"module_changes":{"added":added,"removed":removed,"changed":changed},"db":db,"complete_notice_source_provenance_review":false,"native_inventory_approved":false,"release_accepted":false});
    write_json(&public.join("comparison.json"), &result)?;
    *phase = "compiler-input-catalog-scan";
    let (_, compiler) = observe(driver, COMPILER, arch, "compiler", public, &cache, &db)?;
    result["compiler_input"] = compiler;
    Ok(result)
}
#[test]
fn fixed_syft_inputs_reject_mutation_symlinks_and_existing_targets() {
    let driver = Driver::new().unwrap();
    let input = driver.logs.join("input");
    let target = driver.logs.join("copy");
    write_new(&input, b"public synthetic fixture", 0o600).unwrap();
    assert!(copy_fixed(&input, &target, &"0".repeat(64)).is_err());
    assert!(!target.exists());
    let expected = hash(&input, 1024).unwrap();
    copy_fixed(&input, &target, &expected).unwrap();
    assert!(copy_fixed(&input, &target, &expected).is_err());
    let link = driver.logs.join("link");
    std::os::unix::fs::symlink(&input, &link).unwrap();
    assert!(copy_fixed(&link, &driver.logs.join("another"), &expected).is_err());
}
#[test]
fn syft_modules_require_actual_main_runtime_compiler_and_uniqueness() {
    let valid = json!({"artifacts":[{"name":"github.com/anchore/syft","version":"(devel)","type":"go-module","metadata":{"goCompiledVersion":"go1.27.3"}},{"name":"stdlib","version":"go1.27.3","type":"go-module","metadata":{"goCompiledVersion":"go1.27.3"}}]});
    assert!(modules(&valid, "go1.27.3").is_ok());
    for index in [0, 1] {
        let mut missing = valid.clone();
        missing["artifacts"].as_array_mut().unwrap().remove(index);
        assert!(modules(&missing, "go1.27.3").is_err());
    }
    assert!(modules(&valid, "go1.26.8").is_err());
    let mut duplicate = valid.clone();
    duplicate["artifacts"]
        .as_array_mut()
        .unwrap()
        .push(valid["artifacts"][0].clone());
    assert!(modules(&duplicate, "go1.27.3").is_err());
}
#[test]
fn syft_recorded_evidence_preserves_unqualified_native_source_and_risk_state() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let evidence = read_json(&root.join("inventory/syft-source-candidate-evidence.json")).unwrap();
    for field in [
        "native_amd64_executed",
        "production_inventory_approved",
        "complete_notice_source_provenance_review",
        "release_accepted",
        "consumer_adoption_authorized",
    ] {
        assert_eq!(evidence[field], false);
    }
    assert_eq!(evidence["source_archive_sha256"], SOURCE_HASH);
    assert_eq!(evidence["compiler_only"]["accepted"], 0);
    assert_eq!(evidence["compiler_only"]["blocking"], 4);
    assert_eq!(evidence["dependency_candidate"]["accepted"], 0);
    assert_eq!(evidence["dependency_candidate"]["blocking"], 1);
    assert_eq!(evidence["dependency_candidate"]["patch_sha256"], PATCH_HASH);
    assert_eq!(
        hash(
            &root.join("patches/syft-1.55.0-dependencies.patch.txt"),
            1024 * 1024
        )
        .unwrap(),
        PATCH_HASH
    );
    assert!(risk::receipt(&evidence["dependency_candidate"], "syft").is_err());
}

#[test]
#[ignore = "fixed public native Syft source/compiler measurement; no publication or adoption"]
fn native_syft_compiler_candidate() {
    run_candidate(Work::Compile, ".work/syft-native-candidate");
}
#[test]
#[ignore = "fixed patched Syft dependencies; native measurement, no publication or adoption"]
fn native_syft_dependency_candidate() {
    run_candidate(Work::Patched, ".work/syft-dependency-candidate");
}
fn run_candidate(work: Work, output: &str) {
    let mut driver = Driver::new().expect("Syft candidate driver failed");
    let public = driver.root.join(output);
    mkdir(&public, false).expect("refusing stale Syft candidate evidence");
    write_json(
        &public.join("summary.json"),
        &json!({"schema":1,"status":"error","stage":"startup","release_accepted":false}),
    )
    .unwrap();
    let mut phase = "startup";
    let result = evaluate(&mut driver, &public, &mut phase, work);
    let value = result.as_ref().cloned().unwrap_or_else(|_| {
        let mut partial = read_json(&public.join("comparison.json"))
            .or_else(|_| read_json(&public.join("build.json")))
            .unwrap_or_else(|_| json!({"schema":1}));
        partial["status"] = json!("error");
        partial["stage"] = json!(phase);
        partial["release_accepted"] = json!(false);
        partial
    });
    write_json(&public.join("summary.json"), &value).unwrap();
    assert!(
        result.is_ok(),
        "Syft measurement failed at {phase}; private logs retained"
    );
    assert!(
        value["upstream_race_tests"] == "passed"
            && value["candidate"]["risk"]["blocking"] == 0
            && value["compiler_input"]["risk"]["blocking"] == 0,
        "Syft candidate remains blocked; tests/findings/input issues retained"
    );
}
