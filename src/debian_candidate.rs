//! Local arm64 feasibility test, not a production context or release handoff.
use super::*;
use crate::release::{
    GRYPE, SYFT, db_status, mount, read_json, report_counts, risk, sbom_packages, scanner,
};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

fn copy(input: &Path, output: &Path, expected: &str) -> Result<()> {
    let data = release::bytes(input, 32 * 1024 * 1024)?;
    let digest: String = Sha256::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if digest != expected {
        return Err("candidate input hash mismatch");
    }
    write(output, &data)
}
fn git_version(driver: &mut Driver, image: &str) -> Result<()> {
    let identity = driver
        .logs
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("missing experiment identity")?;
    let name = format!("debian-git-{identity}-{}", driver.sequence);
    let mut args:Vec<_>="run --pull=never --network=none --read-only --user=65532:65532 --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=64 --memory=256m --memory-swap=256m --cpus=1 --ulimit=nofile=256:256 --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 --env=HOME=/tmp --entrypoint=/usr/bin/git".split_ascii_whitespace().collect();
    args.extend(["--name", &name, image, "--version"]);
    let result = driver.docker(&args, 30, false);
    let cleanup = driver.docker(&["rm", "--force", &name], 10, true);
    let output = crate::container_output(result, cleanup)?;
    if release::bytes(&output, 4096)? != b"git version 2.47.3\n"
        || !crate::captured_stderr(&output)?.is_empty()
    {
        return Err("unexpected Debian Git version or diagnostics");
    }
    Ok(())
}
fn evaluate(driver: &mut Driver, phase: &mut &'static str) -> Result<Value> {
    *phase = "native-boundary";
    let (arch, endpoint) = driver.native()?;
    if arch != "arm64" {
        return Err("this fixture only evaluates native arm64");
    }
    *phase = "verified-context";
    let context = driver.logs.join("debian-context");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&context)
        .map_err(|_| "cannot create candidate context")?;
    let payloads = driver
        .root
        .join(".work/check-8774-1793279862827165000/debian-payloads.json");
    if hash(&payloads, 1024 * 1024)?
        != "9a56c7e4a75c9346afee5b60b92958373840b9f565f5f416fa73f21cac633e4c"
    {
        return Err("candidate payload evidence changed");
    }
    let payloads = read_json(&payloads)?;
    for (package, basename, target) in [
        ("git", "git", "git"),
        ("libc6", "libc.so.6", "libc"),
        ("libc6", "ld-linux-aarch64.so.1", "loader"),
        ("libpcre2-8-0", "libpcre2-8.so.0.14.0", "pcre2"),
        ("zlib1g", "libz.so.1.3.1", "zlib"),
        ("git", "copyright", "git-copyright"),
        ("libc6", "copyright", "libc6-copyright"),
        ("libpcre2-8-0", "copyright", "libpcre2-8-0-copyright"),
        ("zlib1g", "copyright", "zlib1g-copyright"),
    ] {
        let records: Vec<_> = payloads["files"]
            .as_array()
            .ok_or("payload records missing")?
            .iter()
            .filter(|file| {
                file["architecture"] == arch
                    && file["package"] == package
                    && Path::new(file["path"].as_str().unwrap_or(""))
                        .file_name()
                        .and_then(|s| s.to_str())
                        == Some(basename)
            })
            .collect();
        if records.len() != 1 {
            return Err("candidate payload selection ambiguous");
        }
        let record = records[0];
        copy(
            &driver.root.join(
                record["capture"]
                    .as_str()
                    .ok_or("missing payload capture")?,
            ),
            &context.join(target),
            record["sha256"].as_str().ok_or("missing payload hash")?,
        )?;
    }
    copy(
        &driver
            .root
            .join(".work/check-98742-1793198486723134000/gitleaks-production-context-10/candidate"),
        &context.join("candidate"),
        "1d199eb20573f760429a52d884c22924deb42ea17d6b12e7afa22f901a7a9f30",
    )?;
    write(
        &context.join("go-notices.txt"),
        &release::gitleaks_candidate::go_notices(&driver.root)?,
    )?;
    let source = driver
        .root
        .join(".work/approval-suppliers/http/debian-src-glibc-1.body");
    if hash(&source, 32 * 1024 * 1024)?
        != "f24aa441021121a79266f0d75242706cab8843a47901fefe74527491807f1998"
    {
        return Err("glibc source archive changed");
    }
    for (member, target) in [
        ("glibc-2.41/COPYING", "GPL-2"),
        ("glibc-2.41/COPYING.LIB", "LGPL-2.1"),
    ] {
        let mut extract = Command::new("tar");
        extract.arg("-xOf").arg(&source).arg(member);
        let out = driver.execute(extract, 60, false, 0)?;
        if !crate::captured_stderr(&out)?.is_empty() {
            return Err("source license extraction diagnostics");
        }
        let text = release::bytes(&out, 1024 * 1024)?;
        if !std::str::from_utf8(&text).is_ok_and(|s| s.trim_start().starts_with("GNU ")) {
            return Err("unexpected source license text");
        }
        write(&context.join(target), &text)?;
    }
    let plan = driver
        .root
        .join(".work/approval-suppliers/debian-runtime-plan.json");
    if hash(&plan, 1024 * 1024)?
        != "41d3a8f66c895b82078d034f94b1a7a2c728959a48022861c3045c9315e7a29d"
    {
        return Err("candidate package plan changed");
    }
    let plan = read_json(&plan)?;
    let mut status = String::new();
    for package in plan["packages"]
        .as_array()
        .ok_or("missing package identities")?
        .iter()
        .filter(|p| p["architecture"] == arch)
    {
        status.push_str(&format!("Package: {}\nVersion: {}\nArchitecture: arm64\nSource: {} ({})\nStatus: install ok installed\nDescription: Selected offline runtime components only, not a complete Debian package installation.\n\n",package["package"].as_str().unwrap(),package["version"].as_str().unwrap(),package["source"].as_str().unwrap(),package["source_version"].as_str().unwrap()));
    }
    write(&context.join("runtime.status"), status.as_bytes())?;
    write(&context.join("selection.json"),&serde_json::to_vec_pretty(&json!({"scope":"experimental selected files; package metadata is conservative source-package attribution, not whole-package installation or runtime completeness","approval":false,"packages":plan["packages"],"source_assets":plan["assets"]})).map_err(|_|"candidate manifest encoding")?)?;
    copy(
        &driver
            .root
            .join("tests/fixtures/gitleaks-debian-arm64/Dockerfile"),
        &context.join("Dockerfile"),
        "63016ca9a58e0c34981871f436e0e0a52e8a70b1abbf095da3c2a92724941c6a",
    )?;
    *phase = "image-build";
    let iid = driver.logs.join("debian.iid");
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
            "--platform=linux/arm64",
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
    *phase = "version-smokes";
    driver.smoke(&image, "gitleaks", &["version"], None)?;
    git_version(driver, &image)?;
    *phase = "filesystem-functional-contract";
    crate::contracts::check(driver, "gitleaks", &image)?;
    *phase = "archive-inventory";
    let archive = driver.logs.join("debian-image.tar");
    driver.docker_archive(&["image", "save", &image], &archive)?;
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o444))
        .map_err(|_| "cannot expose candidate archive")?;
    let config = crate::archive::config_digest(&archive, arch, "local")?;
    driver.docker(&["pull", SYFT], 300, false)?;
    let output = scanner(
        driver,
        SYFT,
        &["docker-archive:/input/image.tar", "-o", "syft-json"],
        &[mount(&archive, "/input/image.tar", true)?],
        false,
        0,
    )?;
    let sbom = read_json(&output)?;
    let packages = sbom_packages(&sbom, &config, arch)?;
    for expected in plan["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["architecture"] == arch)
    {
        if !packages.values().any(|p| {
            p["name"] == expected["package"]
                && p["version"] == expected["version"]
                && p["type"] == "deb"
        }) {
            return Err("candidate SBOM omits a selected native package");
        }
    }
    let sbom_path = driver.logs.join("syft.json");
    write(&sbom_path, &release::bytes(&output, release::JSON_LIMIT)?)?;
    fs::set_permissions(&sbom_path, fs::Permissions::from_mode(0o444))
        .map_err(|_| "cannot expose candidate SBOM")?;
    *phase = "fresh-db";
    driver.docker(&["pull", GRYPE], 300, false)?;
    let cache = mount(&driver.root.join(".work/scans-syft/cache"), "/cache", true)?;
    let db = scanner(
        driver,
        GRYPE,
        &["db", "status", "--output", "json"],
        std::slice::from_ref(&cache),
        false,
        0,
    )?;
    let db = read_json(&db)?;
    let now = chrono::Utc::now();
    db_status(&db, now)?;
    *phase = "vulnerability-capture";
    let output = scanner(
        driver,
        GRYPE,
        &["sbom:/input/syft.json", "--output", "json"],
        &[cache, mount(&sbom_path, "/input/syft.json", true)?],
        false,
        0,
    )?;
    let report = read_json(&output)?;
    let counts = report_counts(&sbom, &packages, &report, &db, now)?;
    let assessment = risk::assess("gitleaks", &sbom, &report)?;
    // Findings are captured, not waived and not treated as release acceptance.
    Ok(
        json!({"scope":"native arm64 replacement feasibility, not a production handoff","status":if assessment["blocking"].as_u64().unwrap_or(1)>0 {"blocked"}else{"evidence-only"},"approval":false,"release_accepted":false,"image":image,"config":config,"filesystem_functional_contract":"passed","upstream_race_tests":"not-rerun; unchanged historical Go executable","gitleaks_sha256":"1d199eb20573f760429a52d884c22924deb42ea17d6b12e7afa22f901a7a9f30","archive_sha256":hash(&archive,release::TAR_LIMIT)?,"sbom_sha256":hash(&sbom_path,release::JSON_LIMIT)?,"report_sha256":hash(&output,release::JSON_LIMIT)?,"counts":counts,"risk":assessment,"database":db,"inventory_packages":packages.len(),"inventory_coverage":"not-approved"}),
    )
}
#[test]
fn candidate_copy_rejects_changed_symlink_and_existing_inputs() {
    let driver = Driver::new().unwrap();
    let input = driver.logs.join("public-input");
    let output = driver.logs.join("copy");
    write(&input, b"public synthetic fixture").unwrap();
    let expected = hash(&input, 1024).unwrap();
    assert!(copy(&input, &output, &"0".repeat(64)).is_err());
    assert!(!output.exists());
    copy(&input, &output, &expected).unwrap();
    assert!(copy(&input, &output, &expected).is_err());
    let link = driver.logs.join("symlink");
    std::os::unix::fs::symlink(&input, &link).unwrap();
    assert!(copy(&link, &driver.logs.join("from-link"), &expected).is_err());
    fs::write(&input, b"changed").unwrap();
    assert!(copy(&input, &driver.logs.join("changed-output"), &expected).is_err());
}
#[test]
#[ignore = "authorized local native arm64 Debian feasibility experiment; no publication, daemon changes or host tracing"]
fn native_debian_gitleaks_feasibility() -> Result<()> {
    let mut driver = Driver::new()?;
    let mut phase = "starting";
    let result = evaluate(&mut driver, &mut phase);
    let summary = match &result {
        Ok(value) => value.clone(),
        Err(_) => {
            json!({"scope":"native arm64 replacement feasibility","status":"failed","phase":phase,"approval":false,"release_accepted":false})
        }
    };
    write(
        &driver.logs.join("debian-candidate.json"),
        &serde_json::to_vec_pretty(&summary).map_err(|_| "candidate summary encoding")?,
    )?;
    result.map(|_| ())
}
