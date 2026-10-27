//! Concrete native scan handoff and owner-gated GHCR publication.
//! Receipts are workflow artifacts, not signatures: the parent workflow must protect their
//! provenance and set the SHA-bound redistribution approval only after owner review.

use super::{Driver, Result, TOOLS};
use chrono::{DateTime, Duration, Utc};
use rustix::fs::{Mode, OFlags, open};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

const SYFT: &str = "anchore/syft:v1.55.0-nonroot@sha256:ec5bdbc745485920c6f444239f0c09ed87b3c4c165ff9433f95bc66b3500fbf9";
const GRYPE: &str = "anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea";
const JSON_LIMIT: u64 = 64 * 1024 * 1024;
const TAR_LIMIT: u64 = 16 * 1024 * 1024 * 1024;
const SEVERITIES: [&str; 7] = [
    "Unknown",
    "Negligible",
    "Low",
    "Medium",
    "High",
    "Critical",
    "ignoredMatches",
];

fn hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn sha(value: &str) -> Result<String> {
    if !hex(value, 40) {
        return Err("GITHUB_SHA must be a full 40-hex source revision");
    }
    Ok(value.to_ascii_lowercase())
}

fn digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|h| hex(h, 64) && h.bytes().all(|b| !b.is_ascii_uppercase()))
}

fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("missing or invalid evidence field")
}

fn fresh(value: &str, now: DateTime<Utc>, hours: i64) -> Result<()> {
    let time = DateTime::parse_from_rfc3339(value).map_err(|_| "invalid evidence timestamp")?;
    if now.signed_duration_since(time) > Duration::hours(hours)
        || time.signed_duration_since(now) > Duration::minutes(5)
    {
        return Err("stale or future-dated evidence");
    }
    Ok(())
}

pub(super) fn db_status(value: &Value, now: DateTime<Utc>) -> Result<()> {
    if value.get("valid").and_then(Value::as_bool) != Some(true)
        || text(value, "/schemaVersion")? != "v6.1.10"
        || value.get("error").is_some_and(|v| v.as_str() != Some(""))
    {
        return Err("invalid Grype database status or schema");
    }
    fresh(text(value, "/built")?, now, 72)
}

// Reject symlinks, FIFOs/devices, oversized input and growth beyond the bound.
// NONBLOCK is important: a substituted FIFO must not block before fstat.
pub(super) fn regular(path: &Path, limit: u64) -> Result<File> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "cannot open nofollow evidence")?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(|_| "cannot inspect evidence")?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > limit {
        return Err("evidence must be a nonempty bounded regular file");
    }
    Ok(file)
}

pub(super) fn bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    regular(path, limit)?
        .take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| "cannot read evidence")?;
    if data.len() as u64 > limit {
        return Err("evidence grew beyond limit");
    }
    Ok(data)
}

pub(super) fn read_json(path: &Path) -> Result<Value> {
    let data = bytes(path, JSON_LIMIT)?;
    let (mut quoted, mut escaped, mut tokens) = (false, false, 0usize);
    for byte in &data {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else if *byte == b'"' {
            quoted = true;
        } else if b"{}[]:,".contains(byte) {
            tokens += 1;
            if tokens > 2_000_000 {
                return Err("JSON structural budget exceeded");
            }
        }
    }
    serde_json::from_slice(&data).map_err(|_| "malformed JSON evidence")
}

fn hash(path: &Path, limit: u64) -> Result<String> {
    let mut file = regular(path, limit)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buffer).map_err(|_| "cannot hash evidence")?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > limit {
            return Err("evidence grew beyond limit");
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn write_new(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|_| "refusing existing or unwritable evidence")?;
    file.write_all(data)
        .and_then(|()| file.sync_all())
        .and_then(|()| file.set_permissions(fs::Permissions::from_mode(mode)))
        .map_err(|_| "cannot write evidence")
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    write_new(
        path,
        &serde_json::to_vec_pretty(value).map_err(|_| "cannot encode evidence")?,
        0o600,
    )
}

fn directory(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)
        .map_err(|_| "missing evidence directory")?
        .is_dir()
    {
        return Err("evidence directory must not be a symlink");
    }
    Ok(())
}

fn mkdir(path: &Path, shared: bool) -> Result<()> {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "refusing stale or unwritable release directory")?;
    // Only mounted leaves are accessible to scanner UID 65532; their parent stays 0700.
    if shared {
        fs::set_permissions(path, fs::Permissions::from_mode(0o777))
            .map_err(|_| "cannot grant scanner output access")?;
    }
    Ok(())
}

fn mount(path: &Path, target: &str, readonly: bool) -> Result<String> {
    let path = path
        .to_str()
        .filter(|p| !p.contains([',', '\n', '\r']))
        .ok_or("invalid scanner mount path")?;
    Ok(format!(
        "type=bind,source={path},target={target}{}",
        if readonly { ",readonly" } else { "" }
    ))
}

// The sole network-enabled scanner invocation is explicit DB refresh. No socket mount,
// host configuration, credentials, registry source or writable input is ever supplied.
pub(super) fn scanner(
    driver: &mut Driver,
    engine: &str,
    args: &[&str],
    mounts: &[String],
    refresh: bool,
    expected_exit: i32,
) -> Result<PathBuf> {
    let run = driver
        .logs
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("missing run identity")?;
    let name = format!("release-{run}-{}", driver.sequence);
    let platform = match std::env::consts::ARCH {
        "x86_64" => "--platform=linux/amd64",
        "aarch64" => "--platform=linux/arm64",
        _ => return Err("unsupported native scanner architecture"),
    };
    let mut command = vec![
        "run",
        "--pull=never",
        platform,
        "--name",
        &name,
        if refresh {
            "--network=bridge"
        } else {
            "--network=none"
        },
        "--read-only",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--cpus=2",
        "--memory=3g",
        "--memory-swap=3g",
        "--pids-limit=128",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=1536m,mode=1777",
        "--env",
        "HOME=/tmp",
        "--env",
        "XDG_CACHE_HOME=/tmp/cache",
        "--env",
        "SYFT_CHECK_FOR_APP_UPDATE=false",
        "--env",
        "GRYPE_DB_CACHE_DIR=/cache",
        "--env",
        "GRYPE_DB_AUTO_UPDATE=false",
        "--env",
        "GRYPE_DB_VALIDATE_AGE=true",
        "--env",
        "GRYPE_DB_MAX_ALLOWED_BUILT_AGE=72h",
        "--env",
        "GRYPE_CHECK_FOR_APP_UPDATE=false",
        "--env",
        "GRYPE_INCLUDE_MATCHER_SUPPRESSIONS=true",
    ];
    for value in mounts {
        command.extend(["--mount", value]);
    }
    command.push(engine);
    command.extend_from_slice(args);
    let result = driver.docker_exit(&command, 900, false, expected_exit);
    let cleanup = driver.docker(&["rm", "--force", &name], 15, true);
    let output = match (result, cleanup) {
        (_, Err(_)) => Err("scanner container cleanup not confirmed"),
        (Err(e), Ok(_)) => Err(e),
        (Ok(_), Ok(_)) if driver.cancelled.load(Ordering::Relaxed) => Err("release cancelled"),
        (Ok(path), Ok(_)) => Ok(path),
    }?;
    if expected_exit == 0 {
        scanner_diagnostics(&super::captured_stderr(&output)?)?;
    }
    Ok(output)
}

// Precision notices also remain blocking without separate policy approval.
// Never enable symbol filtering or waive findings merely to silence a warning.
fn scanner_diagnostics(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        Ok(())
    } else {
        Err("scanner emitted diagnostics; private logs retained")
    }
}

fn sbom_packages<'a>(
    value: &'a Value,
    image: &str,
    arch: &str,
) -> Result<BTreeMap<&'a str, &'a Value>> {
    if text(value, "/descriptor/name")? != "syft"
        || text(value, "/descriptor/version")? != "1.55.0"
        || text(value, "/schema/version")? != "16.1.11"
        || text(value, "/source/type")? != "image"
        || text(value, "/source/metadata/imageID")? != image
        || text(value, "/source/metadata/architecture")? != arch
        || text(value, "/source/metadata/os")? != "linux"
    {
        return Err("SBOM tool or immutable image identity mismatch");
    }
    text(value, "/source/id")?;
    let artifacts = value
        .get("artifacts")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or("SBOM has no package artifacts")?;
    let mut packages = BTreeMap::new();
    for package in artifacts {
        let id = text(package, "/id")?;
        text(package, "/name")?;
        text(package, "/version")?;
        text(package, "/type")?;
        if packages.insert(id, package).is_some() {
            return Err("duplicate SBOM package ID");
        }
    }
    Ok(packages)
}

pub(super) fn no_scan_diagnostics(value: &Value) -> Result<()> {
    for key in ["error", "errors", "alerts", "warnings"] {
        if value.get(key).is_some_and(|value| match value {
            Value::Array(values) => !values.is_empty(),
            Value::Object(values) => !values.is_empty(),
            Value::String(value) => !value.is_empty(),
            _ => true,
        }) {
            return Err("scanner errors or diagnostics require review");
        }
    }
    if value
        .get("alertsByPackage")
        .is_some_and(|value| value.as_array().is_none_or(|values| !values.is_empty()))
    {
        return Err("scanner package alerts require review");
    }
    Ok(())
}

fn report_counts(
    sbom: &Value,
    packages: &BTreeMap<&str, &Value>,
    report: &Value,
    db: &Value,
    now: DateTime<Utc>,
) -> Result<BTreeMap<String, u64>> {
    let mut source = sbom["source"]["metadata"].clone();
    // The pinned Grype presenter normalizes these nil image collections to [].
    for key in ["tags", "repoDigests"] {
        if source.get(key).is_some_and(Value::is_null) {
            source[key] = json!([]);
        }
    }
    if text(report, "/descriptor/name")? != "grype"
        || text(report, "/descriptor/version")? != "0.121.0"
        || text(report, "/source/type")? != "image"
        || report.pointer("/source/target") != Some(&source)
        || report
            .pointer("/descriptor/configuration/include-matcher-suppressions")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("Grype tool, source or suppression coverage mismatch");
    }
    let report_db = report
        .pointer("/descriptor/db/status")
        .ok_or("missing scan DB evidence")?;
    db_status(report_db, now)?;
    if report_db.get("built") != db.get("built")
        || report_db.get("schemaVersion") != db.get("schemaVersion")
    {
        return Err("scan database differs from validated database");
    }
    no_scan_diagnostics(report)?;
    let mut counts: BTreeMap<String, u64> =
        SEVERITIES.into_iter().map(|s| (s.to_owned(), 0)).collect();
    for key in ["matches", "ignoredMatches"] {
        // Grype 0.121.0 omits ignoredMatches when empty (Go omitempty).
        let matches = match report.get(key) {
            None if key == "ignoredMatches" => continue,
            Some(Value::Array(matches)) => matches,
            _ => return Err("missing or malformed vulnerability matches"),
        };
        for finding in matches {
            no_scan_diagnostics(finding)?;
            let package = finding.get("artifact").ok_or("missing finding package")?;
            let source = packages
                .get(text(package, "/id")?)
                .ok_or("finding package absent from SBOM")?;
            for field in ["name", "version", "type"] {
                if package.get(field) != source.get(field) {
                    return Err("finding package identity mismatch");
                }
            }
            text(finding, "/vulnerability/id")?;
            let severity = text(finding, "/vulnerability/severity")?;
            if !SEVERITIES[..6].contains(&severity) {
                return Err("unrecognized vulnerability severity");
            }
            *counts.get_mut(severity).ok_or("unknown severity")? += 1;
            if key == "ignoredMatches" {
                *counts
                    .get_mut("ignoredMatches")
                    .ok_or("missing suppression count")? += 1;
            }
        }
    }
    Ok(counts)
}

fn total(counts: &BTreeMap<String, u64>) -> u64 {
    counts
        .iter()
        .filter(|(key, _)| key.as_str() != "ignoredMatches")
        .map(|(_, count)| count)
        .sum()
}

fn prepare_tool(
    driver: &mut Driver,
    tool: &str,
    arch: &str,
    revision: &str,
    db: Option<&Value>,
) -> Result<Value> {
    let image = driver.check(tool)?;
    super::contracts::check(driver, tool, &image)?;
    let scans = driver.root.join(".work/scans");
    let asset = scans.join(tool);
    mkdir(&asset, false)?;
    let tar = asset.join(format!("{tool}-{arch}.tar"));
    let tar_arg = tar.to_str().ok_or("invalid archive path")?;
    driver.docker(&["image", "save", "--output", tar_arg, &image], 600, false)?;
    regular(&tar, TAR_LIMIT)?;
    let config = super::archive::config_digest(&tar, arch, revision)?;
    fs::set_permissions(&tar, fs::Permissions::from_mode(0o644))
        .map_err(|_| "cannot grant scanner archive read access")?;
    let sbom_path = scanner(
        driver,
        SYFT,
        &[
            "scan",
            "docker-archive:/input/image.tar",
            "--scope",
            "all-layers",
            "--output",
            "syft-json",
        ],
        &[mount(&tar, "/input/image.tar", true)?],
        false,
        0,
    )?;
    let sbom = read_json(&sbom_path)?;
    let packages = sbom_packages(&sbom, &config, arch)?;
    super::coverage::check(&sbom, tool)?;
    let db = db.ok_or("fresh scan database unavailable")?;
    // Only this public, bounded inventory is exposed to the next scanner. Logs
    // remain private; neither scanner gets any writable host report directory.
    let staged = asset.join("input.syft.json");
    write_new(&staged, &bytes(&sbom_path, JSON_LIMIT)?, 0o644)?;
    let report_path = scanner(
        driver,
        GRYPE,
        &["sbom:/input/syft.json", "--output", "json"],
        &[
            mount(&staged, "/input/syft.json", true)?,
            mount(&scans.join("cache"), "/cache", true)?,
        ],
        false,
        0,
    )?;
    let report = read_json(&report_path)?;
    let now = Utc::now();
    let counts = report_counts(&sbom, &packages, &report, db, now)?;
    let count = total(&counts);
    if count == 0 {
        let release = driver.root.join(".work/release");
        let clean_tar = release.join(format!("{tool}-{arch}.tar"));
        let clean_sbom = release.join(format!("{tool}-{arch}.syft.json"));
        let sbom_bytes = bytes(&sbom_path, JSON_LIMIT)?;
        write_new(&clean_sbom, &sbom_bytes, 0o600)?;
        // Rename the saved archive, not a tag/rebuild. Raw scanner evidence remains private.
        fs::rename(&tar, &clean_tar).map_err(|_| "cannot retain clean image archive")?;
        fs::set_permissions(&clean_tar, fs::Permissions::from_mode(0o600))
            .map_err(|_| "cannot secure clean archive")?;
        let receipt = json!({
            "schema": 2, "tool": tool, "source_sha": revision, "arch": arch, "image_id": image, "config_id": config,
            "tar_sha256": hash(&clean_tar, TAR_LIMIT)?, "sbom_sha256": hash(&clean_sbom, JSON_LIMIT)?,
            "count": 0, "counts": counts, "contracts": "passed", "created": now.to_rfc3339(), "db": db,
            "syft": SYFT, "grype": GRYPE,
        });
        write_json(
            &release.join(format!("{tool}-{arch}.receipt.json")),
            &receipt,
        )?;
    }
    Ok(
        json!({"tool": tool, "arch": arch, "status": if count == 0 { "clean" } else { "findings" }, "count": count, "counts": counts}),
    )
}

pub(super) fn prepare(driver: &mut Driver) -> Result<()> {
    let revision = sha(&std::env::var("GITHUB_SHA").map_err(|_| "missing GITHUB_SHA")?)?;
    let (arch, _) = driver.native()?;
    let work = driver.root.join(".work");
    directory(&work)?;
    mkdir(&work.join("release"), false)?;
    mkdir(&work.join("public-release"), false)?;
    mkdir(&work.join("scans"), false)?;
    mkdir(&work.join("scans/cache"), true)?;
    // Retrieval precedes, and is separate from, all offline catalog/analysis runs.
    let setup: Result<Value> = (|| {
        for engine in [SYFT, GRYPE] {
            driver.docker(
                &["pull", "--platform", &format!("linux/{arch}"), engine],
                600,
                false,
            )?;
        }
        let cache = work.join("scans/cache");
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
        // Never put provider paths/URLs/errors into the transferable receipt.
        Ok(json!({"valid": true, "schemaVersion": db["schemaVersion"], "built": db["built"]}))
    })();
    if let Err(error) = &setup {
        write_new(
            &driver.logs.join("scan-setup-blocked.json"),
            json!({"reason": error}).to_string().as_bytes(),
            0o600,
        )?;
    }
    let mut statuses = Vec::new();
    let mut failed = setup.is_err();
    for tool in TOOLS {
        // Even a shared DB failure does not skip other assets' build/catalog checks.
        let result = prepare_tool(driver, tool, arch, &revision, setup.as_ref().ok());
        match result {
            Ok(status) => {
                failed |= status["status"] != "clean";
                statuses.push(status);
            }
            Err(error) => {
                failed = true;
                write_new(
                    &driver.logs.join(format!("{tool}-blocked.json")),
                    json!({"reason": error}).to_string().as_bytes(),
                    0o600,
                )?;
                statuses.push(json!({"tool": tool, "arch": arch, "status": "error"}));
            }
        }
    }
    write_json(
        &work.join("public-release/summary.json"),
        &json!({"source_sha": revision, "arch": arch, "status": if failed { "blocked" } else { "clean" }, "tools": statuses}),
    )?;
    if failed {
        Err("release blocked by findings or errors; see counts-only summary and private scans")
    } else {
        Ok(())
    }
}

fn publish_gate(
    repo: &str,
    reference: &str,
    event: &str,
    approved: &str,
    revision: &str,
    reviewed: &str,
) -> Result<String> {
    let revision = sha(revision)?;
    if !repo.eq_ignore_ascii_case("PRJXAI/devsecops")
        || reference != "refs/heads/main"
        || event != "workflow_dispatch"
        || approved != "true"
    {
        return Err(
            "publication requires the authorized repository, main dispatch and owner approval",
        );
    }
    if reviewed != revision {
        return Err("license/source/provenance owner review must approve this exact source SHA");
    }
    Ok(revision)
}

fn publication_readiness(root: &Path) -> Result<()> {
    let value = read_json(&root.join(".github/publication-readiness.json"))?;
    if value.get("schema").and_then(Value::as_u64) != Some(1)
        || [
            "redistribution_complete",
            "supplier_provenance_reviewed",
            "native_functional_contracts_complete",
        ]
        .iter()
        .any(|field| value.get(*field).and_then(Value::as_bool) != Some(true))
        || value
            .get("blockers")
            .and_then(Value::as_array)
            .is_none_or(|items| !items.is_empty())
    {
        return Err("publication readiness is incomplete or unsupported");
    }
    Ok(())
}

fn receipt(
    value: &Value,
    tool: &str,
    arch: &str,
    revision: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    if !TOOLS.contains(&tool)
        || !["amd64", "arm64"].contains(&arch)
        || value.get("schema").and_then(Value::as_u64) != Some(2)
        || text(value, "/tool")? != tool
        || text(value, "/arch")? != arch
        || text(value, "/source_sha")? != revision
        || !digest(text(value, "/image_id")?)
        || !digest(text(value, "/config_id")?)
        || text(value, "/syft")? != SYFT
        || text(value, "/grype")? != GRYPE
        || value.get("count").and_then(Value::as_u64) != Some(0)
        || value.get("contracts").and_then(Value::as_str) != Some("passed")
    {
        return Err("release receipt identity, scanner pin or clean gate mismatch");
    }
    for key in ["tar_sha256", "sbom_sha256"] {
        let h = text(value, &format!("/{key}"))?;
        if !hex(h, 64) || h != h.to_ascii_lowercase() {
            return Err("malformed receipt hash");
        }
    }
    let counts = value
        .get("counts")
        .and_then(Value::as_object)
        .ok_or("missing receipt counts")?;
    if counts.len() != SEVERITIES.len()
        || SEVERITIES
            .iter()
            .any(|s| counts.get(*s).and_then(Value::as_u64) != Some(0))
    {
        return Err("receipt has findings or missing severity coverage");
    }
    fresh(text(value, "/created")?, now, 24)?;
    db_status(value.get("db").ok_or("missing receipt DB evidence")?, now)
}

struct Asset {
    tool: &'static str,
    arch: &'static str,
    image: String,
    config: String,
    tar: PathBuf,
    tar_hash: String,
}

fn preflight(root: &Path, revision: &str, now: DateTime<Utc>) -> Result<Vec<Asset>> {
    let downloaded = root.join(".work/downloaded");
    directory(&root.join(".work"))?;
    directory(&downloaded)?;
    let mut assets = Vec::new();
    let mut coverage_error = None;
    for arch in ["amd64", "arm64"] {
        let dir = downloaded.join(format!("release-{arch}"));
        directory(&dir)?;
        for tool in TOOLS {
            let value = read_json(&dir.join(format!("{tool}-{arch}.receipt.json")))?;
            receipt(&value, tool, arch, revision, now)?;
            let image = text(&value, "/image_id")?;
            let tar = dir.join(format!("{tool}-{arch}.tar"));
            let sbom = dir.join(format!("{tool}-{arch}.syft.json"));
            if hash(&tar, TAR_LIMIT)? != text(&value, "/tar_sha256")?
                || hash(&sbom, JSON_LIMIT)? != text(&value, "/sbom_sha256")?
            {
                return Err("downloaded release asset hash mismatch");
            }
            let config = super::archive::config_digest(&tar, arch, revision)?;
            if config != text(&value, "/config_id")? {
                return Err("archive config differs from receipt");
            }
            let inventory = read_json(&sbom)?;
            sbom_packages(&inventory, &config, arch)?;
            if let Err(error) = super::coverage::check(&inventory, tool) {
                coverage_error.get_or_insert(error);
            }
            assets.push(Asset {
                tool,
                arch,
                image: image.to_owned(),
                config,
                tar,
                tar_hash: text(&value, "/tar_sha256")?.to_owned(),
            });
        }
    }
    if let Some(error) = coverage_error {
        return Err(error);
    }
    Ok(assets)
}

fn loaded_identity(output: &[u8], expected: &str) -> Result<()> {
    if !digest(expected)
        || std::str::from_utf8(output)
            .map_err(|_| "invalid image load output")?
            .trim()
            != format!("Loaded image ID: {expected}")
    {
        return Err("archive load did not identify exactly the expected image");
    }
    Ok(())
}

fn load_assets(driver: &mut Driver, assets: &[Asset]) -> Result<()> {
    for asset in assets {
        if hash(&asset.tar, TAR_LIMIT)? != asset.tar_hash {
            return Err("release archive changed after preflight");
        }
        let loaded = driver.docker(
            &[
                "image",
                "load",
                "--input",
                asset.tar.to_str().ok_or("invalid archive path")?,
            ],
            600,
            false,
        )?;
        loaded_identity(&bytes(&loaded, 4096)?, &asset.image)?;
        if driver.inspect(&asset.image, asset.arch)? != asset.image {
            return Err("loaded image ID differs from receipt");
        }
    }
    Ok(())
}

fn registry_manifest(driver: &mut Driver, reference: &str) -> Result<(String, Value)> {
    let path = driver.docker(
        &[
            "buildx",
            "imagetools",
            "inspect",
            "--format",
            "{{json .Manifest}}",
            reference,
        ],
        120,
        false,
    )?;
    let description = read_json(&path)?;
    let id = text(&description, "/digest")?;
    if !digest(id) {
        return Err("missing immutable registry manifest digest");
    }
    let repository = reference
        .split('@')
        .next()
        .ok_or("invalid registry reference")?;
    // The references here have no registry port; strip only the final tag.
    let repository = repository
        .rsplit_once(':')
        .map_or(repository, |(repo, _)| repo);
    let immutable = format!("{repository}@{id}");
    let raw = driver.docker(
        &["buildx", "imagetools", "inspect", "--raw", &immutable],
        120,
        false,
    )?;
    if hash(&raw, JSON_LIMIT)? != id.trim_start_matches("sha256:") {
        return Err("registry manifest body digest mismatch");
    }
    Ok((id.to_owned(), read_json(&raw)?))
}

fn index_matches(value: &Value, expected: &[(&str, String)]) -> Result<()> {
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
        return Err("invalid registry index schema");
    }
    let manifests = value
        .get("manifests")
        .and_then(Value::as_array)
        .ok_or("missing registry index members")?;
    if manifests.len() != 2 {
        return Err("registry index must contain exactly two native images");
    }
    let mut seen = BTreeSet::new();
    for manifest in manifests {
        let arch = text(manifest, "/platform/architecture")?;
        if text(manifest, "/platform/os")? != "linux"
            || !seen.insert(arch)
            || !expected.iter().any(|(a, d)| {
                *a == arch && manifest.get("digest").and_then(Value::as_str) == Some(d.as_str())
            })
        {
            return Err("registry index platform/digest mismatch");
        }
    }
    Ok(())
}

pub(super) fn publish(driver: &mut Driver) -> Result<()> {
    let env = |key| std::env::var(key).unwrap_or_default();
    let revision = publish_gate(
        &env("GITHUB_REPOSITORY"),
        &env("GITHUB_REF"),
        &env("GITHUB_EVENT_NAME"),
        &env("DEVSECOPS_PUBLISH_APPROVED"),
        &env("GITHUB_SHA"),
        &env("DEVSECOPS_LICENSE_SOURCE_PROVENANCE_APPROVED_SHA"),
    )?;
    publication_readiness(&driver.root)?;
    // No token is read: docker/login-action supplies Docker credentials externally.
    let assets = preflight(&driver.root, &revision, Utc::now())?;
    driver.native()?;
    publish_preflighted(driver, &assets, &revision)
}

// One concrete post-preflight phase so regression tests exercise the SAME
// load barrier and registry mutation sequence as the authorized entrypoint.
fn publish_preflighted(driver: &mut Driver, assets: &[Asset], revision: &str) -> Result<()> {
    load_assets(driver, assets)?;
    let published = driver.root.join(".work/published");
    mkdir(&published, false)?;
    let mut subjects = String::new();
    let mut references = String::new();
    for tool in TOOLS {
        let repository = format!("ghcr.io/prjxai/devsecops/{tool}");
        let mut members = Vec::new();
        for asset in assets.iter().filter(|a| a.tool == *tool) {
            // Every archive was hash-checked, loaded and identity-checked before this phase.
            let tag = format!("{repository}:sha-{revision}-{}", asset.arch);
            driver.docker(&["image", "tag", &asset.image, &tag], 30, false)?;
            // Publish the verified native member, not its daemon-side OCI index
            // (which can also contain unverified BuildKit attestations).
            driver.docker(
                &[
                    "image",
                    "push",
                    "--platform",
                    &format!("linux/{}", asset.arch),
                    &tag,
                ],
                900,
                false,
            )?;
            let (id, manifest) = registry_manifest(driver, &tag)?;
            if text(&manifest, "/config/digest")? != asset.config
                || manifest
                    .get("layers")
                    .and_then(Value::as_array)
                    .is_none_or(|a| a.is_empty())
            {
                return Err("pushed registry manifest differs from native image ID");
            }
            references.push_str(&format!("{repository}@{id}\n"));
            members.push((asset.arch, id));
        }
        let tag = format!("{repository}:sha-{revision}");
        let mut command = vec!["buildx", "imagetools", "create", "--tag", &tag];
        let inputs: Vec<_> = members
            .iter()
            .map(|(_, id)| format!("{repository}@{id}"))
            .collect();
        command.extend(inputs.iter().map(String::as_str));
        driver.docker(&command, 180, false)?;
        let (id, manifest) = registry_manifest(driver, &tag)?;
        index_matches(&manifest, &members)?;
        subjects.push_str(&format!(
            "{}  {repository}\n",
            id.trim_start_matches("sha256:")
        ));
        references.push_str(&format!("{repository}@{id}\n"));
    }
    write_new(
        &published.join("subjects.checksums"),
        subjects.as_bytes(),
        0o600,
    )?;
    write_new(
        &published.join("references.txt"),
        references.as_bytes(),
        0o600,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const REV: &str = "0123456789abcdef0123456789abcdef01234567";
    fn image() -> String {
        format!("sha256:{}", "a".repeat(64))
    }
    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-26T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }
    fn db() -> Value {
        json!({"valid": true, "schemaVersion": "v6.1.10", "built": now().to_rfc3339()})
    }
    fn sbom() -> Value {
        json!({"descriptor": {"name": "syft", "version": "1.55.0"}, "schema": {"version": "16.1.11"},
            "source": {"id": "catalog", "type": "image", "metadata": {"imageID": image(), "architecture": "amd64", "os": "linux"}},
            "artifacts": [{"id": "pkg", "name": "synthetic", "version": "1", "type": "go-module"}]})
    }
    // Test the complete parse/identity/count composition; production carries
    // the already validated borrowed package index through the scan.
    fn report_counts(
        sbom: &Value,
        report: &Value,
        image: &str,
        arch: &str,
        db: &Value,
        now: DateTime<Utc>,
    ) -> Result<BTreeMap<String, u64>> {
        let packages = sbom_packages(sbom, image, arch)?;
        super::report_counts(sbom, &packages, report, db, now)
    }
    fn report() -> Value {
        json!({"descriptor": {"name": "grype", "version": "0.121.0", "db": {"status": db(), "providers": {}}, "configuration": {"include-matcher-suppressions": true}},
            "source": {"type": "image", "target": sbom()["source"]["metadata"]}, "matches": []})
    }
    fn clean_receipt() -> Value {
        json!({"schema": 2, "tool": "syft", "arch": "amd64", "source_sha": REV, "image_id": image(), "config_id": image(),
            "syft": SYFT, "grype": GRYPE, "count": 0, "contracts": "passed", "created": now().to_rfc3339(), "db": db(),
            "tar_sha256": "b".repeat(64), "sbom_sha256": "c".repeat(64),
            "counts": SEVERITIES.into_iter().map(|s| (s, 0u64)).collect::<BTreeMap<_, _>>()})
    }

    #[test]
    fn gates_reject_every_unapproved_context() {
        assert!(
            publish_gate(
                "prjxai/DEVSECOPS",
                "refs/heads/main",
                "workflow_dispatch",
                "true",
                REV,
                REV
            )
            .is_ok()
        );
        for (repo, reference, event, approved, revision, reviewed) in [
            (
                "other/devsecops",
                "refs/heads/main",
                "workflow_dispatch",
                "true",
                REV,
                REV,
            ),
            (
                "PRJXAI/devsecops",
                "refs/pull/1/merge",
                "workflow_dispatch",
                "true",
                REV,
                REV,
            ),
            (
                "PRJXAI/devsecops",
                "refs/heads/main",
                "push",
                "true",
                REV,
                REV,
            ),
            (
                "PRJXAI/devsecops",
                "refs/heads/main",
                "workflow_dispatch",
                "TRUE",
                REV,
                REV,
            ),
            (
                "PRJXAI/devsecops",
                "refs/heads/main",
                "workflow_dispatch",
                "true",
                "abc",
                REV,
            ),
            (
                "PRJXAI/devsecops",
                "refs/heads/main",
                "workflow_dispatch",
                "true",
                REV,
                "",
            ),
        ] {
            assert!(publish_gate(repo, reference, event, approved, revision, reviewed).is_err());
        }
        for invalid in ["", "../main", "0123456789abcdef0123456789abcdef0123456g"] {
            assert!(sha(invalid).is_err());
        }
    }

    #[test]
    fn readiness_file_cannot_be_overridden_by_dispatch_approval() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.0.join(".github")).unwrap();
        let path = fixture.0.join(".github/publication-readiness.json");
        assert!(
            publish_gate(
                "PRJXAI/devsecops",
                "refs/heads/main",
                "workflow_dispatch",
                "true",
                REV,
                REV
            )
            .is_ok()
        );
        assert!(publication_readiness(&fixture.0).is_err());
        let good = json!({"schema":1,"redistribution_complete":true,"supplier_provenance_reviewed":true,"native_functional_contracts_complete":true,"blockers":[]});
        fs::write(&path, good.to_string()).unwrap();
        assert!(publication_readiness(&fixture.0).is_ok());
        for field in [
            "schema",
            "redistribution_complete",
            "supplier_provenance_reviewed",
            "native_functional_contracts_complete",
            "blockers",
        ] {
            let mut missing = good.clone();
            missing.as_object_mut().unwrap().remove(field);
            fs::write(&path, missing.to_string()).unwrap();
            assert!(publication_readiness(&fixture.0).is_err(), "{field}");
            let invalid = if field == "schema" {
                vec![json!(2), json!("1"), Value::Null]
            } else if field == "blockers" {
                vec![json!(["unresolved"]), json!({}), json!(false), Value::Null]
            } else {
                vec![json!(false), json!("true"), Value::Null]
            };
            for value in invalid {
                let mut bad = good.clone();
                bad[field] = value;
                fs::write(&path, bad.to_string()).unwrap();
                assert!(publication_readiness(&fixture.0).is_err(), "{field}");
            }
        }
        fs::write(&path, "{truncated").unwrap();
        assert!(publication_readiness(&fixture.0).is_err());
    }

    #[test]
    fn db_fails_closed_for_missing_invalid_stale_future_or_wrong_schema() {
        assert!(db_status(&db(), now()).is_ok());
        for (key, value) in [
            ("valid", json!(false)),
            ("valid", Value::Null),
            ("schemaVersion", json!("v6.1.9")),
            ("built", json!((now() - Duration::hours(73)).to_rfc3339())),
            ("built", json!((now() + Duration::minutes(6)).to_rfc3339())),
            ("built", json!("not a time")),
            ("error", json!("synthetic error")),
        ] {
            let mut bad = db();
            bad[key] = value;
            assert!(db_status(&bad, now()).is_err());
        }
        assert!(db_status(&json!({}), now()).is_err());
    }

    #[test]
    fn all_severities_and_suppressions_block_clean_status() {
        assert_eq!(
            total(&report_counts(&sbom(), &report(), &image(), "amd64", &db(), now()).unwrap()),
            0
        );
        for severity in &SEVERITIES[..6] {
            for field in ["matches", "ignoredMatches"] {
                let mut value = report();
                value[field] = json!([{"artifact": sbom()["artifacts"][0], "vulnerability": {"id": "SYNTHETIC-1", "severity": severity}}]);
                let counts =
                    report_counts(&sbom(), &value, &image(), "amd64", &db(), now()).unwrap();
                assert_eq!(total(&counts), 1);
                assert_eq!(counts[*severity], 1);
                assert_eq!(
                    counts["ignoredMatches"],
                    u64::from(field == "ignoredMatches")
                );
            }
        }
    }

    #[test]
    fn malformed_reports_and_wrong_catalog_bindings_are_errors() {
        for pointer in [
            "/descriptor/name",
            "/descriptor/version",
            "/source/type",
            "/source/target/imageID",
            "/descriptor/db/status/built",
            "/descriptor/configuration/include-matcher-suppressions",
            "/matches",
        ] {
            let mut bad = report();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(report_counts(&sbom(), &bad, &image(), "amd64", &db(), now()).is_err());
        }
        for artifacts in [
            json!([]),
            Value::Null,
            json!([sbom()["artifacts"][0], sbom()["artifacts"][0]]),
        ] {
            let mut bad = sbom();
            bad["artifacts"] = artifacts;
            assert!(report_counts(&bad, &report(), &image(), "amd64", &db(), now()).is_err());
        }
        for (id, severity) in [("absent", "High"), ("pkg", "new severity")] {
            let mut bad = report();
            let mut package = sbom()["artifacts"][0].clone();
            package["id"] = json!(id);
            bad["matches"] = json!([{"artifact": package, "vulnerability": {"id": "SYNTHETIC-1", "severity": severity}}]);
            assert!(report_counts(&sbom(), &bad, &image(), "amd64", &db(), now()).is_err());
        }
        let mut bad = report();
        bad["ignoredMatches"] = Value::Null;
        assert!(report_counts(&sbom(), &bad, &image(), "amd64", &db(), now()).is_err());
        assert!(sbom_packages(&sbom(), &format!("sha256:{}", "b".repeat(64)), "amd64").is_err());
        assert!(sbom_packages(&sbom(), &image(), "arm64").is_err());
    }

    #[test]
    fn receipt_requires_complete_current_clean_native_evidence() {
        assert!(receipt(&clean_receipt(), "syft", "amd64", REV, now()).is_ok());
        for (pointer, value) in [
            ("/source_sha", json!("f".repeat(40))),
            ("/arch", json!("arm64")),
            ("/tool", json!("grype")),
            ("/syft", json!("latest")),
            ("/grype", json!("latest")),
            ("/count", json!(1)),
            ("/counts/Unknown", json!(1)),
            ("/counts/ignoredMatches", json!(1)),
            (
                "/created",
                json!((now() - Duration::hours(25)).to_rfc3339()),
            ),
            (
                "/created",
                json!((now() + Duration::minutes(6)).to_rfc3339()),
            ),
            ("/tar_sha256", json!("x".repeat(64))),
            ("/sbom_sha256", Value::Null),
            ("/db/valid", json!(false)),
        ] {
            let mut bad = clean_receipt();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(receipt(&bad, "syft", "amd64", REV, now()).is_err());
        }
        let mut bad = clean_receipt();
        bad["counts"].as_object_mut().unwrap().remove("Negligible");
        assert!(receipt(&bad, "syft", "amd64", REV, now()).is_err());
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "devsecops-release-test-{}-{stamp}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            mkdir(&root, false).unwrap();
            Self(root)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn evidence_rejects_symlinks_devices_directories_oversize_and_bad_json() {
        let fixture = Fixture::new();
        let file = fixture.0.join("evidence.json");
        write_new(&file, b"{}", 0o600).unwrap();
        assert!(read_json(&file).is_ok());
        assert!(bytes(&file, 1).is_err());
        assert!(write_new(&file, b"overwrite", 0o600).is_err());
        let link = fixture.0.join("link.json");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_json(&link).is_err());
        assert!(regular(&fixture.0, JSON_LIMIT).is_err());
        assert!(regular(Path::new("/dev/null"), JSON_LIMIT).is_err());
        #[cfg(target_os = "linux")]
        {
            let fifo = fixture.0.join("fifo");
            rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, Mode::RUSR | Mode::WUSR).unwrap();
            assert!(regular(&fifo, JSON_LIMIT).is_err());
        }
        fs::write(&file, b"{truncated").unwrap();
        assert!(read_json(&file).is_err());
        fs::write(&file, b"").unwrap();
        assert!(read_json(&file).is_err());
        assert!(read_json(&fixture.0.join("missing")).is_err());
    }

    #[test]
    fn leaf_checks_do_not_claim_immutable_parent_authority() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("owned-parent");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("archive");
        fs::write(&path, "original public fixture").unwrap();
        directory(&parent).unwrap();
        let before = hash(&path, 128).unwrap();
        // A same-UID actor can replace the parent after validation. This is outside
        // the documented runner authority boundary, not a capability-safe handoff.
        fs::rename(&parent, fixture.0.join("previous-parent")).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(&path, "replacement public fixture").unwrap();
        assert_ne!(hash(&path, 128).unwrap(), before);
        assert_eq!(bytes(&path, 128).unwrap(), b"replacement public fixture");
    }

    #[test]
    fn json_structural_budget_is_independent_of_transfer_size() {
        let fixture = Fixture::new();
        let path = fixture.0.join("dense.json");
        fs::write(&path, format!("[{}0]", "0,".repeat(2_000_000))).unwrap();
        assert_eq!(
            read_json(&path).unwrap_err(),
            "JSON structural budget exceeded"
        );
        fs::write(
            &path,
            serde_json::to_vec(&json!({"text": "{}".repeat(1_000_001)})).unwrap(),
        )
        .unwrap();
        assert!(read_json(&path).is_ok());
    }

    #[test]
    fn preflight_requires_all_eighteen_hash_bound_assets_before_any_docker_use() {
        let fixture = Fixture::new();
        let work = fixture.0.join(".work");
        mkdir(&work, false).unwrap();
        let downloaded = work.join("downloaded");
        mkdir(&downloaded, false).unwrap();
        for arch in ["amd64", "arm64"] {
            let dir = downloaded.join(format!("release-{arch}"));
            mkdir(&dir, false).unwrap();
            for tool in TOOLS {
                let tar = dir.join(format!("{tool}-{arch}.tar"));
                let path = dir.join(format!("{tool}-{arch}.syft.json"));
                let config = super::super::archive::fixture(&tar, arch, REV);
                let mut bom = sbom();
                bom["source"]["metadata"]["imageID"] = json!(config);
                bom["source"]["metadata"]["architecture"] = json!(arch);
                write_json(&path, &bom).unwrap();
                let mut value = clean_receipt();
                value["tool"] = json!(tool);
                value["arch"] = json!(arch);
                value["config_id"] = json!(config);
                value["tar_sha256"] = json!(hash(&tar, TAR_LIMIT).unwrap());
                value["sbom_sha256"] = json!(hash(&path, JSON_LIMIT).unwrap());
                write_json(&dir.join(format!("{tool}-{arch}.receipt.json")), &value).unwrap();
            }
        }
        // Structurally valid handoffs still cannot bypass missing reviewed
        // payload/architecture coverage. Check later structural faults take
        // precedence, proving all eighteen handoffs are validated before return.
        let coverage = "payload coverage lacks reviewed native architecture evidence";
        assert_eq!(preflight(&fixture.0, REV, now()).err(), Some(coverage));
        let last = downloaded.join("release-arm64/docker-arm64.receipt.json");
        let original = bytes(&last, JSON_LIMIT).unwrap();
        let mut bad: Value = serde_json::from_slice(&original).unwrap();
        bad["count"] = json!(1);
        fs::write(&last, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert_eq!(
            preflight(&fixture.0, REV, now()).err(),
            Some("release receipt identity, scanner pin or clean gate mismatch")
        );
        fs::write(&last, &original).unwrap();
        assert!(preflight(&fixture.0, &"f".repeat(40), now()).is_err());
        assert!(preflight(&fixture.0, REV, now() + Duration::hours(25)).is_err());
        let tar = downloaded.join("release-arm64/docker-arm64.tar");
        let original_tar = fs::read(&tar).unwrap();
        fs::write(&tar, b"changed archive").unwrap();
        assert_eq!(
            preflight(&fixture.0, REV, now()).err(),
            Some("downloaded release asset hash mismatch")
        );
        fs::write(&tar, &original_tar).unwrap();
        fs::remove_file(&last).unwrap();
        let error = preflight(&fixture.0, REV, now()).err();
        assert!(error.is_some());
        assert_ne!(error, Some(coverage));
        write_new(&last, &original, 0o600).unwrap();
        assert_eq!(preflight(&fixture.0, REV, now()).err(), Some(coverage));
    }

    #[test]
    fn scanner_diagnostics_reject_even_the_pinned_precision_notice() {
        let warning = b"[0000]  WARN go binary packages were found but none carry function symbols; go vulnerability matching falls back to module granularity and may report false positives. if scanning an SBOM, regenerate it with symbol capture enabled for more precise results.\n";
        assert!(scanner_diagnostics(b"").is_ok());
        assert!(scanner_diagnostics(warning).is_err());
        for extra in [b"SYNTHETIC_PRIVATE_DIAGNOSTIC".as_slice(), warning, b"\n"] {
            assert!(scanner_diagnostics(&[warning, extra].concat()).is_err());
        }
        for wrong in [
            b"[abcd]  WARN invalid".as_slice(),
            b"[0000] ERROR database",
            b"[0000]  WARN incomplete inventory",
            &[255],
        ] {
            assert!(scanner_diagnostics(wrong).is_err());
        }
    }

    #[test]
    #[ignore = "approved public candidate SBOM/cache capture replay; offline, no image publication"]
    fn native_bounded_scan_captures_preserve_all_module_granularity_findings() {
        let mut driver = Driver::new().unwrap();
        let (arch, _) = driver.native().unwrap();
        let scans = driver.root.join(".work/scans");
        let cache = mount(&scans.join("cache"), "/cache", true).unwrap();
        let status = scanner(
            &mut driver,
            GRYPE,
            &["db", "status", "--output", "json"],
            std::slice::from_ref(&cache),
            false,
            0,
        )
        .unwrap();
        let db = read_json(&status).unwrap();
        db_status(&db, Utc::now()).unwrap();
        let mut statuses = Vec::new();
        for tool in ["syft", "grype", "gitleaks"] {
            let input = scans.join(tool).join("input.syft.json");
            let bom = read_json(&input).unwrap();
            let primary = driver.sequence + 1;
            let result = scanner(
                &mut driver,
                GRYPE,
                &["sbom:/input/syft.json", "--output", "json"],
                &[
                    cache.clone(),
                    mount(&input, "/input/syft.json", true).unwrap(),
                ],
                false,
                0,
            );
            assert!(
                result.is_err(),
                "unapproved precision notice must still block"
            );
            let output = driver.logs.join(format!("{primary}-stdout.log"));
            assert!(scanner_diagnostics(&super::super::captured_stderr(&output).unwrap()).is_err());
            let report = read_json(&output).unwrap();
            let counts = report_counts(
                &bom,
                &report,
                text(&bom, "/source/metadata/imageID").unwrap(),
                arch,
                &db,
                Utc::now(),
            )
            .unwrap();
            assert!(
                total(&counts) > 0,
                "known vulnerable candidate unexpectedly clean"
            );
            let size = regular(&output, crate::LOG_LIMIT as u64)
                .unwrap()
                .metadata()
                .unwrap()
                .len();
            statuses.push(json!({"tool": tool, "status": "blocked-diagnostics-and-findings", "count": total(&counts), "counts": counts, "report_bytes": size}));
        }
        write_json(&driver.root.join(".work/tasks-native-verified-counts.json"), &json!({"scope":"blocked offline candidate capture inspection, not scan/release acceptance", "arch": arch, "tools": statuses})).unwrap();
    }

    #[test]
    fn source_normalization_only_accepts_the_pinned_presenter_transformation() {
        let mut bom = sbom();
        let mut value = report();
        for key in ["tags", "repoDigests"] {
            bom["source"]["metadata"][key] = Value::Null;
            value["source"]["target"][key] = json!([]);
        }
        assert!(report_counts(&bom, &value, &image(), "amd64", &db(), now()).is_ok());
        value["source"]["target"]["tags"] = json!(["other"]);
        assert!(report_counts(&bom, &value, &image(), "amd64", &db(), now()).is_err());
        value = report();
        value["alertsByPackage"] = json!([{"synthetic": true}]);
        assert!(report_counts(&sbom(), &value, &image(), "amd64", &db(), now()).is_err());
        for key in ["error", "errors", "alerts", "warnings"] {
            for diagnostic in [
                json!(["SYNTHETIC_PRIVATE_DIAGNOSTIC"]),
                Value::Null,
                json!(false),
            ] {
                let mut value = report();
                value[key] = diagnostic;
                assert!(report_counts(&sbom(), &value, &image(), "amd64", &db(), now()).is_err());
            }
        }
    }

    #[test]
    #[ignore = "Rust-only subprocess fixture for the all-assets-before-push test"]
    fn publication_load_fixture() {
        let root = PathBuf::from(std::env::var_os("DEVSECOPS_FAKE_ROOT").unwrap());
        let mut driver = Driver::new().unwrap();
        driver.root = root.clone();
        // Real preflight rejects incomplete catalogs. Then exercise the actual
        // post-preflight load AND mutation sequence with synthetic handoffs;
        // deleting its load barrier must make this regression fail.
        assert!(publish(&mut driver).is_err());
        assert!(!root.join("commands").exists());
        let mut assets = Vec::new();
        for arch in ["amd64", "arm64"] {
            let dir = root.join(format!(".work/downloaded/release-{arch}"));
            for tool in TOOLS {
                let value = read_json(&dir.join(format!("{tool}-{arch}.receipt.json"))).unwrap();
                assets.push(Asset {
                    tool,
                    arch,
                    image: text(&value, "/image_id").unwrap().to_owned(),
                    config: text(&value, "/config_id").unwrap().to_owned(),
                    tar: dir.join(format!("{tool}-{arch}.tar")),
                    tar_hash: text(&value, "/tar_sha256").unwrap().to_owned(),
                });
            }
        }
        driver.native().unwrap();
        assert!(publish_preflighted(&mut driver, &assets, REV).is_err());
        let commands = fs::read_to_string(root.join("commands")).unwrap();
        assert_eq!(
            commands
                .lines()
                .filter(|line| line.starts_with("image load "))
                .count(),
            18
        );
        assert!(
            !commands
                .lines()
                .any(|line| line.starts_with("image push ") || line.starts_with("image tag "))
        );
    }

    #[test]
    fn bad_eighteenth_archive_causes_zero_pushes_even_with_preloaded_expected_ids() {
        let fixture = Fixture::new();
        let github = fixture.0.join(".github");
        fs::create_dir(&github).unwrap();
        write_json(&github.join("publication-readiness.json"), &json!({"schema":1,"redistribution_complete":true,"supplier_provenance_reviewed":true,"native_functional_contracts_complete":true,"blockers":[]})).unwrap();
        let work = fixture.0.join(".work");
        mkdir(&work, false).unwrap();
        let downloaded = work.join("downloaded");
        mkdir(&downloaded, false).unwrap();
        for arch in ["amd64", "arm64"] {
            let dir = downloaded.join(format!("release-{arch}"));
            mkdir(&dir, false).unwrap();
            let id = format!(
                "sha256:{}",
                if arch == "amd64" { "a" } else { "b" }.repeat(64)
            );
            for tool in TOOLS {
                let tar = dir.join(format!("{tool}-{arch}.tar"));
                let sbom_path = dir.join(format!("{tool}-{arch}.syft.json"));
                let config = super::super::archive::fixture(&tar, arch, REV);
                write_new(&tar.with_extension("id"), id.as_bytes(), 0o600).unwrap();
                let mut bom = sbom();
                bom["source"]["metadata"]["imageID"] = json!(config);
                bom["source"]["metadata"]["architecture"] = json!(arch);
                write_json(&sbom_path, &bom).unwrap();
                let mut value = clean_receipt();
                value["tool"] = json!(tool);
                value["arch"] = json!(arch);
                value["image_id"] = json!(id);
                value["config_id"] = json!(config);
                value["created"] = json!(Utc::now().to_rfc3339());
                value["db"]["built"] = json!(Utc::now().to_rfc3339());
                value["tar_sha256"] = json!(hash(&tar, TAR_LIMIT).unwrap());
                value["sbom_sha256"] = json!(hash(&sbom_path, JSON_LIMIT).unwrap());
                write_json(&dir.join(format!("{tool}-{arch}.receipt.json")), &value).unwrap();
            }
        }
        let bin = fixture.0.join("bin");
        fs::create_dir(&bin).unwrap();
        let mut driver = Driver::new().unwrap();
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
        for mode in ["wrong", "multiple", "malformed"] {
            let _ = fs::remove_file(fixture.0.join("commands"));
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "release::tests::publication_load_fixture",
                    "--ignored",
                    "--nocapture",
                ])
                .env("PATH", &path)
                .env("DEVSECOPS_FAKE_ROOT", &fixture.0)
                .env("DEVSECOPS_FAKE_LOAD", mode)
                .env("GITHUB_REPOSITORY", "PRJXAI/devsecops")
                .env("GITHUB_REF", "refs/heads/main")
                .env("GITHUB_EVENT_NAME", "workflow_dispatch")
                .env("DEVSECOPS_PUBLISH_APPROVED", "true")
                .env("GITHUB_SHA", REV)
                .env("DEVSECOPS_LICENSE_SOURCE_PROVENANCE_APPROVED_SHA", REV)
                .env_remove("DOCKER_HOST")
                .env_remove("DOCKER_CONTEXT");
            driver.execute(child, 30, false, 0).unwrap();
        }
    }

    #[test]
    #[ignore = "requires the approved local native Docker daemon; no registry writes"]
    fn native_id_only_archive_roundtrip() {
        let mut driver = Driver::new().unwrap();
        let image = driver.check("syft").unwrap();
        let archive = driver.logs.join("roundtrip.tar");
        driver
            .docker(
                &[
                    "image",
                    "save",
                    "--output",
                    archive.to_str().unwrap(),
                    &image,
                ],
                120,
                false,
            )
            .unwrap();
        // Expected image is already present: successful load must still identify the archive.
        let output = driver
            .docker(
                &["image", "load", "--input", archive.to_str().unwrap()],
                120,
                false,
            )
            .unwrap();
        loaded_identity(&bytes(&output, 4096).unwrap(), &image).unwrap();
        let (arch, _) = driver.native().unwrap();
        assert_eq!(driver.inspect(&image, arch).unwrap(), image);
    }

    #[test]
    fn load_output_must_identify_the_archive_not_a_preexisting_image() {
        let id = image();
        assert!(loaded_identity(format!("Loaded image ID: {id}\n").as_bytes(), &id).is_ok());
        for output in [
            "".into(),
            format!("Loaded image ID: sha256:{}", "b".repeat(64)),
            format!("Loaded image ID: {id}\nLoaded image ID: {id}"),
            format!("Loaded image: mutable:tag\nLoaded image ID: {id}"),
            format!("cached existing {id}"),
        ] {
            assert!(loaded_identity(output.as_bytes(), &id).is_err());
        }
        assert!(loaded_identity(&[255], &id).is_err());
    }

    #[test]
    #[ignore = "approved local native Docker; verifies public license bytes without registry writes"]
    fn native_inlined_license_bytes_and_modes() {
        let mut driver = Driver::new().unwrap();
        for (tool, expected) in [
            (
                "kind",
                "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1",
            ),
            (
                "kustomize",
                "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1",
            ),
            (
                "kubectl",
                "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
            ),
        ] {
            let image = driver.check(tool).unwrap();
            let name = format!(
                "license-{}-{}",
                driver.logs.file_name().unwrap().to_str().unwrap(),
                tool
            );
            let destination = driver.logs.join(format!("{tool}-LICENSE"));
            let result = (|| -> Result<()> {
                driver.docker(
                    &[
                        "create",
                        "--name",
                        &name,
                        "--network=none",
                        "--read-only",
                        "--user=65532:65532",
                        "--cap-drop=ALL",
                        "--security-opt=no-new-privileges",
                        &image,
                    ],
                    30,
                    false,
                )?;
                driver.docker(
                    &[
                        "cp",
                        &format!("{name}:/usr/share/licenses/{tool}/LICENSE"),
                        destination.to_str().ok_or("invalid license fixture path")?,
                    ],
                    30,
                    false,
                )?;
                if hash(&destination, 32 * 1024)? != expected
                    || regular(&destination, 32 * 1024)?
                        .metadata()
                        .map_err(|_| "cannot inspect license mode")?
                        .permissions()
                        .mode()
                        & 0o777
                        != 0o444
                {
                    return Err("packaged license bytes or mode changed");
                }
                Ok(())
            })();
            let cleanup = driver.docker(&["rm", "--force", &name], 15, true);
            assert!(result.is_ok(), "{tool}: {result:?}");
            assert!(cleanup.is_ok(), "{tool}: license fixture removal failed");
        }
    }

    #[test]
    fn index_rejects_missing_duplicate_wrong_digest_or_platform() {
        let members = vec![
            ("amd64", image()),
            ("arm64", format!("sha256:{}", "b".repeat(64))),
        ];
        let good = json!({"schemaVersion": 2, "manifests": members.iter().map(|(a, d)| json!({"digest": d, "platform": {"os": "linux", "architecture": a}})).collect::<Vec<_>>()});
        assert!(index_matches(&good, &members).is_ok());
        for pointer in [
            "/manifests/0/digest",
            "/manifests/0/platform/os",
            "/manifests/0/platform/architecture",
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(index_matches(&bad, &members).is_err());
        }
        let mut bad = good.clone();
        bad["manifests"][1] = bad["manifests"][0].clone();
        assert!(index_matches(&bad, &members).is_err());
        bad["manifests"] = json!([]);
        assert!(index_matches(&bad, &members).is_err());
    }
}
