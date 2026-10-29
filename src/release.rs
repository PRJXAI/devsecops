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

#[path = "release_risk.rs"]
mod risk;

#[path = "gitleaks_candidate.rs"]
pub(super) mod gitleaks_candidate;

const SYFT: &str = "anchore/syft:v1.55.0-nonroot@sha256:ec5bdbc745485920c6f444239f0c09ed87b3c4c165ff9433f95bc66b3500fbf9";
const GRYPE: &str = "anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea";
const JSON_LIMIT: u64 = 64 * 1024 * 1024;
pub(super) const TAR_LIMIT: u64 = 16 * 1024 * 1024 * 1024;
const SEVERITIES: [&str; 7] = [
    "Unknown",
    "Negligible",
    "Low",
    "Medium",
    "High",
    "Critical",
    "ignoredMatches",
];

pub(super) fn tool_identity(value: &str) -> Result<&'static str> {
    TOOLS
        .iter()
        .copied()
        .find(|tool| *tool == value)
        .ok_or("unknown release tool")
}

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
        let diagnostics = super::captured_stderr(&output)?;
        // Owner-approved precision notice applies only to this pinned offline
        // vulnerability invocation, never Syft, DB setup or functional controls.
        if engine == GRYPE && args == ["sbom:/input/syft.json", "--output", "json"] && !refresh {
            risk::diagnostics(&diagnostics)?;
        } else {
            scanner_diagnostics(&diagnostics)?;
        }
    }
    Ok(output)
}

// Default diagnostic policy remains strict. The only exception is classified
// separately above; it does not change matching precision or hide findings.
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
    no_scan_diagnostics(value)?;
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

// Public attribution is deliberately a small source-defined vocabulary. Never
// serialize an error as a public reason, even when its current type is &'static str.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparationStage {
    SyftPull,
    GrypePull,
    DatabaseRefresh,
    DatabaseStatus,
    DatabaseValidation,
    BuildSmoke,
    FilesystemContract,
    FunctionalContract,
    ArchiveSave,
    ArchiveIdentity,
    CatalogScan,
    CatalogValidation,
    InventoryCoverage,
    DatabaseRequired,
    VulnerabilityScan,
    ReportValidation,
    ReleaseHandoff,
}

impl PreparationStage {
    fn code(self) -> &'static str {
        match self {
            Self::SyftPull => "syft-pull",
            Self::GrypePull => "grype-pull",
            Self::DatabaseRefresh => "database-refresh",
            Self::DatabaseStatus => "database-status",
            Self::DatabaseValidation => "database-validation",
            Self::BuildSmoke => "build-smoke",
            Self::FilesystemContract => "filesystem-contract",
            Self::FunctionalContract => "functional-contract",
            Self::ArchiveSave => "archive-save",
            Self::ArchiveIdentity => "archive-identity",
            Self::CatalogScan => "catalog-scan",
            Self::CatalogValidation => "catalog-validation",
            Self::InventoryCoverage => "inventory-coverage",
            Self::DatabaseRequired => "database-required",
            Self::VulnerabilityScan => "vulnerability-scan",
            Self::ReportValidation => "report-validation",
            Self::ReleaseHandoff => "release-handoff",
        }
    }
}

fn preparation_failure(stage: PreparationStage, error: &str) -> Value {
    // Exact matches only: dynamic text, prefixes and future errors fall back to
    // stage-failed. The raw explanation remains in the private capped captures.
    let reason = match error {
        "command timed out" => "command-timeout",
        "command output limit exceeded" => "output-limit",
        "unexpected command exit; private logs retained" => "command-exit",
        "cannot start command; private logs retained" => "command-start",
        "check cancelled" | "release cancelled" | "contract cancelled" => "cancelled",
        "command failed and process cleanup was not confirmed" => "process-cleanup",
        "check failed and container cleanup was not confirmed"
        | "container cleanup failed; private logs retained"
        | "scanner container cleanup not confirmed"
        | "contract failed and container cleanup was not confirmed"
        | "contract container cleanup failed; private logs retained" => "container-cleanup",
        "scanner emitted diagnostics; private logs retained"
        | "functional analysis emitted diagnostics; private logs retained" => "analysis-stderr",
        "scanner errors or diagnostics require review"
        | "scanner package alerts require review" => "analysis-json-diagnostics",
        "malformed JSON evidence" => "invalid-json",
        "evidence must be a nonempty bounded regular file"
        | "evidence grew beyond limit"
        | "JSON structural budget exceeded" => "evidence-limit-or-type",
        "refusing stale or unwritable release directory"
        | "refusing existing or unwritable evidence" => "evidence-path-unavailable",
        "unexpected tool version; review supplier and version metadata together" => {
            "version-mismatch"
        }
        "image identity, user or architecture check failed" | "built image identity mismatch" => {
            "image-identity"
        }
        "unexpected effective image entrypoint" => "entrypoint-mismatch",
        "unsupported filesystem member type" => "filesystem-member-type",
        "unsafe filesystem path" => "filesystem-path",
        "unexpected filesystem link target" => "filesystem-link-target",
        "forbidden filesystem executable" | "forbidden filesystem executable alias" => {
            "filesystem-forbidden-executable"
        }
        "critical filesystem file must be regular" => "filesystem-critical-file-type",
        "SBOM tool or immutable image identity mismatch" => "catalog-identity",
        "SBOM has no package artifacts" => "catalog-empty",
        "SBOM omitted or changed a captured payload/dependency tuple" => "inventory-tuple-mismatch",
        "UNKNOWN payload/dependency versions block catalog coverage" => "inventory-unknown-version",
        "payload coverage lacks reviewed native architecture evidence" => {
            "inventory-architecture-unreviewed"
        }
        "Rust payload/dependency/compiler inventory is absent" => "inventory-rust-missing",
        "Docker CLI payload version and embedded dependencies remain unresolved" => {
            "inventory-docker-incomplete"
        }
        "kind Docker provider payload inventory has not been reviewed" => {
            "inventory-provider-unreviewed"
        }
        "Go payload location has no captured compiler inventory"
        | "Go payload compiler inventory differs from native capture" => {
            "inventory-compiler-mismatch"
        }
        "cargo-deny functional contract blocked: pinned compiler-free runtime cannot prove Cargo/index/advisory coverage" => {
            "cargo-deny-coverage-unproven"
        }
        "kind functional contract blocked: provider inventory and separately authorized control-plane validation required" => {
            "kind-control-plane-unapproved"
        }
        "fresh scan database unavailable" => "shared-setup-unavailable",
        "invalid Grype database status or schema" => "database-invalid",
        "stale or future-dated evidence" => "evidence-not-fresh",
        _ => "stage-failed",
    };
    let mut status = json!({"status":"error", "stage":stage.code(), "reason":reason});
    if stage == PreparationStage::DatabaseRequired {
        status["blocked_by"] = json!("shared-setup");
    }
    status
}

fn prepare_tool(
    driver: &mut Driver,
    tool: &str,
    arch: &str,
    revision: &str,
    db: Option<&Value>,
    stage: &mut PreparationStage,
) -> Result<Value> {
    *stage = PreparationStage::BuildSmoke;
    let image = driver.check(tool)?;
    *stage = PreparationStage::FilesystemContract;
    super::filesystem::check(driver, tool, &image)?;
    *stage = PreparationStage::FunctionalContract;
    super::contracts::functional(driver, tool, &image)?;
    *stage = PreparationStage::ArchiveSave;
    let scans = driver.root.join(format!(".work/scans-{tool}"));
    let asset = scans.join(tool);
    mkdir(&asset, false)?;
    let tar = asset.join(format!("{tool}-{arch}.tar"));
    driver.docker_archive(&["image", "save", &image], &tar)?;
    regular(&tar, TAR_LIMIT)?;
    *stage = PreparationStage::ArchiveIdentity;
    let config = super::archive::config_digest(&tar, arch, revision)?;
    fs::set_permissions(&tar, fs::Permissions::from_mode(0o644))
        .map_err(|_| "cannot grant scanner archive read access")?;
    *stage = PreparationStage::CatalogScan;
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
    *stage = PreparationStage::CatalogValidation;
    let sbom = read_json(&sbom_path)?;
    let packages = sbom_packages(&sbom, &config, arch)?;
    *stage = PreparationStage::InventoryCoverage;
    super::coverage::check(&sbom, tool)?;
    *stage = PreparationStage::DatabaseRequired;
    let db = db.ok_or("fresh scan database unavailable")?;
    *stage = PreparationStage::VulnerabilityScan;
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
    *stage = PreparationStage::ReportValidation;
    let report = read_json(&report_path)?;
    let now = Utc::now();
    let counts = report_counts(&sbom, &packages, &report, db, now)?;
    let count = total(&counts);
    let decision = risk::assess(tool, &sbom, &report)?;
    let status = risk::status(&decision);
    let diagnostics = risk::diagnostics(&super::captured_stderr(&report_path)?)?;
    let report_sha256 = hash(&report_path, JSON_LIMIT)?;
    if status != "findings" {
        *stage = PreparationStage::ReleaseHandoff;
        let release = driver.root.join(format!(".work/release-{tool}"));
        let clean_tar = release.join(format!("{tool}-{arch}.tar"));
        let clean_sbom = release.join(format!("{tool}-{arch}.syft.json"));
        let sbom_bytes = bytes(&sbom_path, JSON_LIMIT)?;
        write_new(&clean_sbom, &sbom_bytes, 0o600)?;
        // Rename the saved archive, not a tag/rebuild. Raw scanner evidence remains private.
        fs::rename(&tar, &clean_tar).map_err(|_| "cannot retain release image archive")?;
        fs::set_permissions(&clean_tar, fs::Permissions::from_mode(0o600))
            .map_err(|_| "cannot secure release archive")?;
        let receipt = json!({
            "schema": 3, "tool": tool, "source_sha": revision, "arch": arch, "image_id": image, "config_id": config,
            "tar_sha256": hash(&clean_tar, TAR_LIMIT)?, "sbom_sha256": hash(&clean_sbom, JSON_LIMIT)?,
            "report_sha256":report_sha256, "risk":decision, "status":status, "diagnostics":diagnostics,
            "count": count, "counts": counts, "contracts": "passed", "created": now.to_rfc3339(), "db": db,
            "syft": SYFT, "grype": GRYPE,
        });
        risk::receipt(&receipt, tool)?;
        write_json(
            &release.join(format!("{tool}-{arch}.receipt.json")),
            &receipt,
        )?;
    }
    Ok(
        json!({"tool": tool, "arch": arch, "status": status, "count": count, "counts": counts, "risk":decision, "diagnostics":diagnostics, "report_sha256":report_sha256}),
    )
}

/// Capture public native inventories for review, never release handoffs. This
/// deliberately does not turn incomplete coverage into a release receipt.
pub(super) fn catalog(driver: &mut Driver, tool: &str) -> Result<()> {
    let tool = tool_identity(tool)?;
    let revision = sha(&std::env::var("GITHUB_SHA").map_err(|_| "missing GITHUB_SHA")?)?;
    let (arch, _) = driver.native()?;
    let output = driver.root.join(format!(".work/catalog-evidence-{tool}"));
    mkdir(&output, false)?;
    write_json(
        &output.join("summary.json"),
        &json!({"schema":1,"scope":"public native inventory review only; not scan or release acceptance","source_sha":revision,"arch":arch,"status":"error","tools":[]}),
    )?;
    driver.docker(
        &["pull", "--platform", &format!("linux/{arch}"), SYFT],
        600,
        false,
    )?;
    let result = (|| -> Result<Value> {
        let image = driver.check(tool)?;
        let archive = driver.logs.join(format!("catalog-{tool}-{arch}.tar"));
        driver.docker_archive(&["image", "save", &image], &archive)?;
        let config = super::archive::config_digest(&archive, arch, &revision)?;
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o644))
            .map_err(|_| "cannot share public catalog archive")?;
        let capture = scanner(
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
            &[mount(&archive, "/input/image.tar", true)?],
            false,
            0,
        )?;
        let document = read_json(&capture)?;
        sbom_packages(&document, &config, arch)?;
        let covered = super::coverage::check(&document, tool).is_ok();
        let name = format!("{tool}.syft.json");
        let target = output.join(&name);
        write_new(&target, &bytes(&capture, JSON_LIMIT)?, 0o600)?;
        Ok(
            json!({"tool":tool,"status":"captured-not-release","coverage":if covered {"captured-profile"} else {"blocked"},"engine_id":image,"config_id":config,"archive_sha256":hash(&archive,TAR_LIMIT)?,"sbom":name,"sbom_sha256":hash(&target,JSON_LIMIT)?}),
        )
    })();
    let failed = result.is_err();
    let status = match result {
        Ok(status) => status,
        Err(reason) => {
            write_new(
                &driver.logs.join(format!("catalog-{tool}-blocked.json")),
                json!({"reason":reason}).to_string().as_bytes(),
                0o600,
            )?;
            json!({"tool":tool,"status":"error"})
        }
    };
    let complete = output.join("summary.complete.json");
    write_json(
        &complete,
        &json!({"schema":1,"scope":"public native inventory review only; not scan or release acceptance","source_sha":revision,"arch":arch,"syft":SYFT,"created":Utc::now().to_rfc3339(),"status":if failed {"error"} else {"captured-not-release"},"tools":[status]}),
    )?;
    fs::rename(&complete, output.join("summary.json"))
        .map_err(|_| "cannot publish native catalog status")?;
    if failed {
        Err("native catalog capture incomplete; private diagnostics retained")
    } else {
        Ok(())
    }
}

pub(super) fn prepare(driver: &mut Driver, tool: &str) -> Result<()> {
    let tool = tool_identity(tool)?;
    let revision = sha(&std::env::var("GITHUB_SHA").map_err(|_| "missing GITHUB_SHA")?)?;
    let (arch, _) = driver.native()?;
    let work = driver.root.join(".work");
    directory(&work)?;
    mkdir(&work.join(format!("release-{tool}")), false)?;
    let public = work.join(format!("public-release-{tool}"));
    mkdir(&public, false)?;
    let scans = work.join(format!("scans-{tool}"));
    mkdir(&scans, false)?;
    mkdir(&scans.join("cache"), true)?;
    // Retrieval precedes, and is separate from, all offline catalog/analysis runs.
    let mut setup_stage = PreparationStage::SyftPull;
    let setup: Result<Value> = (|| {
        for (engine, stage) in [
            (SYFT, PreparationStage::SyftPull),
            (GRYPE, PreparationStage::GrypePull),
        ] {
            setup_stage = stage;
            driver.docker(
                &["pull", "--platform", &format!("linux/{arch}"), engine],
                600,
                false,
            )?;
        }
        let cache = scans.join("cache");
        setup_stage = PreparationStage::DatabaseRefresh;
        scanner(
            driver,
            GRYPE,
            &["db", "update"],
            &[mount(&cache, "/cache", false)?],
            true,
            0,
        )?;
        setup_stage = PreparationStage::DatabaseStatus;
        let status = scanner(
            driver,
            GRYPE,
            &["db", "status", "--output", "json"],
            &[mount(&cache, "/cache", true)?],
            false,
            0,
        )?;
        setup_stage = PreparationStage::DatabaseValidation;
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
    let setup_status = match &setup {
        Ok(_) => json!({"status":"ready"}),
        Err(error) => preparation_failure(setup_stage, error),
    };
    // A scanner setup failure must not hide an earlier independent tool failure.
    let mut stage = PreparationStage::BuildSmoke;
    let status = match prepare_tool(
        driver,
        tool,
        arch,
        &revision,
        setup.as_ref().ok(),
        &mut stage,
    ) {
        Ok(status) => status,
        Err(error) => {
            write_new(
                &driver.logs.join(format!("{tool}-blocked.json")),
                json!({"reason": error}).to_string().as_bytes(),
                0o600,
            )?;
            let mut status = preparation_failure(stage, error);
            status["tool"] = json!(tool);
            status["arch"] = json!(arch);
            status
        }
    };
    let failed = setup.is_err()
        || !["clean", "accepted-risk"].contains(&status["status"].as_str().unwrap_or(""));
    write_json(
        &public.join("summary.json"),
        &json!({"schema":1, "source_sha": revision, "tool":tool, "arch": arch, "status": if failed { "blocked" } else { status["status"].as_str().unwrap_or("blocked") }, "setup": setup_status, "tools": [status]}),
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

fn publication_readiness(root: &Path, tool: &str) -> Result<()> {
    let tool = tool_identity(tool)?;
    let value = read_json(&root.join(format!(".github/publication-readiness/{tool}.json")))?;
    if value.get("schema").and_then(Value::as_u64) != Some(2)
        || value.get("tool").and_then(Value::as_str) != Some(tool)
        || value.get("repository").and_then(Value::as_str)
            != Some(format!("ghcr.io/prjxai/devsecops/{tool}").as_str())
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
        || value.get("schema").and_then(Value::as_u64) != Some(3)
        || text(value, "/tool")? != tool
        || text(value, "/arch")? != arch
        || text(value, "/source_sha")? != revision
        || !digest(text(value, "/image_id")?)
        || !digest(text(value, "/config_id")?)
        || text(value, "/syft")? != SYFT
        || text(value, "/grype")? != GRYPE
        || value.get("contracts").and_then(Value::as_str) != Some("passed")
    {
        return Err("release receipt identity, scanner pin or contract gate mismatch");
    }
    for key in ["tar_sha256", "sbom_sha256", "report_sha256"] {
        let h = text(value, &format!("/{key}"))?;
        if !hex(h, 64) || h != h.to_ascii_lowercase() {
            return Err("malformed receipt hash");
        }
    }
    risk::receipt(value, tool)?;
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
    assessment: Value,
}

fn public_assessment(value: &Value) -> Value {
    json!({"arch":value["arch"],"status":value["status"],"count":value["count"],
        "counts":value["counts"],"risk":value["risk"],"diagnostics":value["diagnostics"],
        "report_sha256":value["report_sha256"]})
}

fn preflight(
    root: &Path,
    tools: &[&'static str],
    revision: &str,
    now: DateTime<Utc>,
) -> Result<Vec<Asset>> {
    let downloaded = root.join(".work/downloaded");
    directory(&root.join(".work"))?;
    directory(&downloaded)?;
    let mut assets = Vec::new();
    let mut coverage_error = None;
    for arch in ["amd64", "arm64"] {
        for tool in tools {
            tool_identity(tool)?;
            let dir = downloaded.join(format!("release-{tool}-{arch}"));
            directory(&dir)?;
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
            risk::inventory(&value, tool, &inventory)?;
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
                assessment: public_assessment(&value),
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

pub(super) fn publish(driver: &mut Driver, tool: &str) -> Result<()> {
    let tool = tool_identity(tool)?;
    let env = |key| std::env::var(key).unwrap_or_default();
    let revision = publish_gate(
        &env("GITHUB_REPOSITORY"),
        &env("GITHUB_REF"),
        &env("GITHUB_EVENT_NAME"),
        &env("DEVSECOPS_PUBLISH_APPROVED"),
        &env("GITHUB_SHA"),
        &env("DEVSECOPS_LICENSE_SOURCE_PROVENANCE_APPROVED_SHA"),
    )?;
    if env("DEVSECOPS_LICENSE_SOURCE_PROVENANCE_APPROVED_TOOL") != tool {
        return Err("license/source/provenance owner review must approve this exact tool");
    }
    publication_readiness(&driver.root, tool)?;
    // No token is read: docker/login-action supplies Docker credentials externally.
    let assets = preflight(&driver.root, &[tool], &revision, Utc::now())?;
    driver.native()?;
    publish_preflighted(driver, &[tool], &assets, &revision)
}

// One concrete post-preflight phase so regression tests exercise the SAME
// load barrier and registry mutation sequence as the authorized entrypoint.
fn publish_preflighted(
    driver: &mut Driver,
    tools: &[&str],
    assets: &[Asset],
    revision: &str,
) -> Result<()> {
    // Defense in depth: no omitted, duplicate or cross-tool member reaches tagging.
    if tools.is_empty()
        || tools.iter().copied().collect::<BTreeSet<_>>().len() != tools.len()
        || assets.len() != tools.len() * 2
    {
        return Err("publication asset scope mismatch");
    }
    for tool in tools {
        tool_identity(tool)?;
        for arch in ["amd64", "arm64"] {
            if assets
                .iter()
                .filter(|asset| asset.tool == *tool && asset.arch == arch)
                .count()
                != 1
            {
                return Err("publication asset scope mismatch");
            }
        }
    }
    load_assets(driver, assets)?;
    for tool in tools {
        let published = driver.root.join(format!(".work/published-{tool}"));
        mkdir(&published, false)?;
        let mut subjects = String::new();
        let mut references = String::new();
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
        write_json(
            &published.join("release-status.json"),
            &json!({
                "schema":1,"tool":tool,"source_sha":revision,"repository":repository,"manifest_digest":id,
                "status":if assets.iter().filter(|asset| asset.tool == *tool).any(|asset| asset.assessment["status"] == "accepted-risk") { "accepted-risk" } else { "clean" },
                "architectures":assets.iter().filter(|asset| asset.tool == *tool).map(|asset| &asset.assessment).collect::<Vec<_>>()
            }),
        )?;
        write_new(
            &published.join("subjects.checksums"),
            subjects.as_bytes(),
            0o600,
        )?;
        write_new(
            &published.join("references.txt"),
            references.as_bytes(),
            0o600,
        )?;
    }
    Ok(())
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
        json!({"schema": 3, "tool": "syft", "arch": "amd64", "source_sha": REV, "image_id": image(), "config_id": image(),
            "syft": SYFT, "grype": GRYPE, "count": 0, "contracts": "passed", "created": now().to_rfc3339(), "db": db(),
            "tar_sha256": "b".repeat(64), "sbom_sha256": "c".repeat(64), "report_sha256":"d".repeat(64),
            "risk":{"policy":risk::POLICY,"accepted":0,"blocking":0,"exceptions":[]},"status":"clean","diagnostics":"none",
            "counts": SEVERITIES.into_iter().map(|s| (s, 0u64)).collect::<BTreeMap<_, _>>()})
    }

    #[test]
    fn tool_identities_and_readiness_are_independent_and_fail_closed() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let retired = read_json(&root.join(".github/publication-readiness.json")).unwrap();
        assert_eq!(retired["schema"], 0);
        assert_eq!(retired["retired"], true);
        assert!(retired.get("redistribution_complete").is_none());
        let directory = root.join(".github/publication-readiness");
        let mut names = BTreeSet::new();
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            names.insert(entry.file_name().into_string().unwrap());
        }
        assert_eq!(
            names,
            TOOLS.iter().map(|tool| format!("{tool}.json")).collect()
        );
        for tool in TOOLS {
            assert_eq!(tool_identity(tool).unwrap(), *tool);
            let value = read_json(&root.join(format!(".github/publication-readiness/{tool}.json")))
                .unwrap();
            assert_eq!(value["schema"], 2);
            assert_eq!(value["tool"], *tool);
            assert_eq!(
                value["repository"],
                format!("ghcr.io/prjxai/devsecops/{tool}")
            );
            let blockers = value["blockers"].as_array().unwrap();
            assert!(
                blockers
                    .iter()
                    .all(|blocker| blocker.as_str().is_some_and(|text| !text.trim().is_empty()))
            );
            let mut approved = true;
            for field in [
                "redistribution_complete",
                "supplier_provenance_reviewed",
                "native_functional_contracts_complete",
            ] {
                approved &= value[field].as_bool().unwrap();
            }
            assert_eq!(
                publication_readiness(root, tool).is_ok(),
                approved && blockers.is_empty()
            );
        }
        for unknown in [
            "",
            "all",
            "Syft",
            "../syft",
            "syft;id",
            "gitleaks-candidate",
            "syft/../../docker",
            "syft\n",
        ] {
            assert!(tool_identity(unknown).is_err());
            assert!(publication_readiness(root, unknown).is_err());
        }
    }

    #[test]
    fn asset_scope_rejects_missing_duplicate_foreign_or_unselected_members_before_docker() {
        let mut driver = Driver::new().unwrap();
        let asset = |tool, arch| Asset {
            tool,
            arch,
            image: image(),
            config: image(),
            tar: driver.logs.join("absent.tar"),
            tar_hash: "b".repeat(64),
            assessment: public_assessment(&clean_receipt()),
        };
        let bad = [
            vec![],
            vec![asset("syft", "amd64")],
            vec![asset("syft", "amd64"), asset("syft", "amd64")],
            vec![asset("syft", "amd64"), asset("grype", "arm64")],
            vec![asset("syft", "amd64"), asset("syft", "s390x")],
            vec![
                asset("syft", "amd64"),
                asset("syft", "arm64"),
                asset("docker", "arm64"),
            ],
        ];
        for assets in bad {
            assert_eq!(
                publish_preflighted(&mut driver, &["syft"], &assets, REV),
                Err("publication asset scope mismatch")
            );
        }
        assert_eq!(
            publish_preflighted(&mut driver, &[], &[], REV),
            Err("publication asset scope mismatch")
        );
        assert_eq!(
            publish_preflighted(&mut driver, &["syft", "syft"], &[], REV),
            Err("publication asset scope mismatch")
        );
    }

    #[test]
    fn public_preparation_failures_use_only_exact_allowlisted_codes() {
        for (stage, code) in [
            (PreparationStage::SyftPull, "syft-pull"),
            (PreparationStage::GrypePull, "grype-pull"),
            (PreparationStage::DatabaseRefresh, "database-refresh"),
            (PreparationStage::DatabaseStatus, "database-status"),
            (PreparationStage::DatabaseValidation, "database-validation"),
            (PreparationStage::BuildSmoke, "build-smoke"),
            (PreparationStage::FilesystemContract, "filesystem-contract"),
            (PreparationStage::FunctionalContract, "functional-contract"),
            (PreparationStage::ArchiveSave, "archive-save"),
            (PreparationStage::ArchiveIdentity, "archive-identity"),
            (PreparationStage::CatalogScan, "catalog-scan"),
            (PreparationStage::CatalogValidation, "catalog-validation"),
            (PreparationStage::InventoryCoverage, "inventory-coverage"),
            (PreparationStage::DatabaseRequired, "database-required"),
            (PreparationStage::VulnerabilityScan, "vulnerability-scan"),
            (PreparationStage::ReportValidation, "report-validation"),
            (PreparationStage::ReleaseHandoff, "release-handoff"),
        ] {
            for error in [
                "SYNTHETIC_PRIVATE_DIAGNOSTIC",
                "https://example.invalid/private?signature=synthetic",
                "command timed out: SYNTHETIC_PRIVATE_DIAGNOSTIC",
                "future unreviewed static error",
                "",
            ] {
                let mut expected = json!({"status":"error","stage":code,"reason":"stage-failed"});
                if stage == PreparationStage::DatabaseRequired {
                    expected["blocked_by"] = json!("shared-setup");
                }
                // Exact whole-object equality rejects raw text or extra fields too.
                assert_eq!(preparation_failure(stage, error), expected);
            }
        }
        for (error, code) in [
            ("command timed out", "command-timeout"),
            ("command output limit exceeded", "output-limit"),
            (
                "unexpected command exit; private logs retained",
                "command-exit",
            ),
            (
                "scanner container cleanup not confirmed",
                "container-cleanup",
            ),
            (
                "scanner emitted diagnostics; private logs retained",
                "analysis-stderr",
            ),
            (
                "scanner errors or diagnostics require review",
                "analysis-json-diagnostics",
            ),
            (
                "UNKNOWN payload/dependency versions block catalog coverage",
                "inventory-unknown-version",
            ),
            ("stale or future-dated evidence", "evidence-not-fresh"),
        ] {
            assert_eq!(
                preparation_failure(PreparationStage::VulnerabilityScan, error),
                json!({"status":"error","stage":"vulnerability-scan","reason":code})
            );
        }
        assert_eq!(
            preparation_failure(
                PreparationStage::DatabaseRequired,
                "fresh scan database unavailable"
            ),
            json!({"status":"error","stage":"database-required","reason":"shared-setup-unavailable","blocked_by":"shared-setup"})
        );
    }

    #[test]
    #[ignore = "Rust-only subprocess fixture invoked by the active preparation regression test"]
    fn preparation_failure_fixture() {
        let root = PathBuf::from(std::env::var_os("DEVSECOPS_FAKE_ROOT").unwrap());
        mkdir(&root.join(".work"), false).unwrap();
        let mut driver = Driver::new().unwrap();
        driver.root = root.clone();
        // Stale unrelated work must not block the selected tool.
        mkdir(&root.join(".work/release-cargo-deny"), false).unwrap();
        assert!(prepare(&mut driver, "syft").is_err());
        let summary = read_json(&root.join(".work/public-release-syft/summary.json")).unwrap();
        let mode = std::env::var("DEVSECOPS_FAKE_PREPARE").unwrap();
        let (stage, reason) = match mode.as_str() {
            "pull" => ("syft-pull", "command-exit"),
            "refresh" => ("database-refresh", "command-exit"),
            "status" => ("database-status", "command-exit"),
            "validation" => ("database-validation", "database-invalid"),
            _ => panic!("unsupported fixture mode"),
        };
        assert_eq!(
            summary["setup"],
            json!({"status":"error","stage":stage,"reason":reason})
        );
        assert_eq!(summary["source_sha"], REV);
        assert_eq!(summary["status"], "blocked");
        let statuses = summary["tools"].as_array().unwrap();
        assert_eq!(summary["tool"], "syft");
        assert_eq!(statuses.len(), 1);
        for (status, tool) in statuses.iter().zip(["syft"]) {
            // Shared setup failure must not overwrite an independent build failure.
            assert_eq!(
                status,
                &json!({"tool":tool,"arch":summary["arch"],"status":"error","stage":"build-smoke","reason":"command-exit"})
            );
        }
        assert_eq!(
            fs::read_dir(root.join(".work/release-syft"))
                .unwrap()
                .count(),
            0
        );
        assert!(!summary.to_string().contains("SYNTHETIC_PRIVATE_DIAGNOSTIC"));
        let commands = fs::read_to_string(root.join("commands")).unwrap();
        assert!(commands.contains("images/syft/Dockerfile"));
        assert!(!commands.contains("images/cargo-deny/Dockerfile"));
        assert_eq!(
            commands
                .lines()
                .filter(|line| line.contains("buildx build"))
                .count(),
            1
        );
        let runs = commands
            .lines()
            .filter(|line| line.starts_with("run "))
            .count();
        let removals = commands
            .lines()
            .filter(|line| line.starts_with("rm --force "))
            .count();
        assert_eq!(runs, removals);
        assert_eq!(
            runs,
            match mode.as_str() {
                "pull" => 0,
                "refresh" => 1,
                _ => 2,
            }
        );
        // Raw supplier output remains available only in private capped logs.
        let mut retained = false;
        for entry in fs::read_dir(&driver.logs).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "log") {
                let metadata = fs::metadata(&path).unwrap();
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
                assert!(metadata.len() <= super::super::LOG_LIMIT as u64);
                retained |= fs::read_to_string(&path)
                    .unwrap()
                    .contains("SYNTHETIC_PRIVATE_DIAGNOSTIC");
            }
        }
        assert!(retained);
    }

    #[test]
    fn shared_setup_failures_are_distinct_from_tool_failures_and_keep_raw_output_private() {
        let fixture = Fixture::new();
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
        for mode in ["pull", "refresh", "status", "validation"] {
            let root = fixture.0.join(mode);
            mkdir(&root, false).unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "release::tests::preparation_failure_fixture",
                    "--ignored",
                    "--nocapture",
                ])
                .env("PATH", &path)
                .env("DEVSECOPS_FAKE_ROOT", &root)
                .env("DEVSECOPS_FAKE_PREPARE", mode)
                .env("GITHUB_SHA", REV)
                .env_remove("DOCKER_HOST")
                .env_remove("DOCKER_CONTEXT");
            driver.execute(child, 30, false, 0).unwrap();
        }
    }

    #[test]
    fn catalog_evidence_does_not_satisfy_release_receipts_or_handoff_paths() {
        let value = json!({"schema":1,"scope":"public native inventory review only; not scan or release acceptance","tool":"syft","status":"captured-not-release","coverage":"captured-profile","source_sha":REV,"arch":"amd64"});
        assert!(receipt(&value, "syft", "amd64", REV, now()).is_err());
        let fixture = Fixture::new();
        let work = fixture.0.join(".work");
        mkdir(&work, false).unwrap();
        let catalogs = work.join("catalog-evidence");
        mkdir(&catalogs, false).unwrap();
        write_json(&catalogs.join("summary.json"), &value).unwrap();
        assert!(preflight(&fixture.0, &["syft"], REV, now()).is_err());
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
        fs::create_dir_all(fixture.0.join(".github/publication-readiness")).unwrap();
        let path = fixture.0.join(".github/publication-readiness/syft.json");
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
        assert!(publication_readiness(&fixture.0, "syft").is_err());
        let good = json!({"schema":2,"tool":"syft","repository":"ghcr.io/prjxai/devsecops/syft","redistribution_complete":true,"supplier_provenance_reviewed":true,"native_functional_contracts_complete":true,"blockers":[]});
        fs::write(&path, good.to_string()).unwrap();
        // Missing, malformed and blocked siblings do not veto this approval.
        let sibling = fixture
            .0
            .join(".github/publication-readiness/cargo-deny.json");
        for contents in ["{truncated", "{\"blockers\":[\"coverage unproven\"]}"] {
            fs::write(&sibling, contents).unwrap();
            assert!(publication_readiness(&fixture.0, "syft").is_ok());
            assert!(publication_readiness(&fixture.0, "cargo-deny").is_err());
        }
        // A copied approval is not transferable to another tool.
        fs::write(&sibling, good.to_string()).unwrap();
        assert!(publication_readiness(&fixture.0, "cargo-deny").is_err());
        assert!(publication_readiness(&fixture.0, "gitleaks").is_err());
        for field in [
            "schema",
            "tool",
            "repository",
            "redistribution_complete",
            "supplier_provenance_reviewed",
            "native_functional_contracts_complete",
            "blockers",
        ] {
            let mut missing = good.clone();
            missing.as_object_mut().unwrap().remove(field);
            fs::write(&path, missing.to_string()).unwrap();
            assert!(
                publication_readiness(&fixture.0, "syft").is_err(),
                "{field}"
            );
            let invalid = if field == "schema" {
                vec![json!(1), json!("2"), Value::Null]
            } else if field == "tool" || field == "repository" {
                vec![
                    json!("gitleaks"),
                    json!("ghcr.io/prjxai/devsecops/gitleaks"),
                    Value::Null,
                ]
            } else if field == "blockers" {
                vec![json!(["unresolved"]), json!({}), json!(false), Value::Null]
            } else {
                vec![json!(false), json!("true"), Value::Null]
            };
            for value in invalid {
                let mut bad = good.clone();
                bad[field] = value;
                fs::write(&path, bad.to_string()).unwrap();
                assert!(
                    publication_readiness(&fixture.0, "syft").is_err(),
                    "{field}"
                );
            }
        }
        fs::write(&path, "{truncated").unwrap();
        assert!(publication_readiness(&fixture.0, "syft").is_err());
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
    fn reviewed_risk_receipts_are_nonzero_visible_scoped_and_not_clean() {
        let mut value = clean_receipt();
        value["tool"] = json!("gitleaks");
        value["count"] = json!(1);
        value["counts"]["Unknown"] = json!(1);
        value["status"] = json!("accepted-risk");
        value["diagnostics"] = json!("go-module-granularity");
        value["risk"] = json!({"policy":risk::POLICY,"accepted":1,"blocking":0,"exceptions":["gitleaks-openpgp-no-fix-v1"]});
        assert!(receipt(&value, "gitleaks", "amd64", REV, now()).is_ok());
        assert_eq!(public_assessment(&value)["count"], 1);
        assert_eq!(public_assessment(&value)["status"], "accepted-risk");
        for (pointer, bad) in [
            ("/schema", json!(2)),
            ("/status", json!("clean")),
            ("/risk/accepted", json!(0)),
            ("/risk/blocking", json!(1)),
            ("/risk/exceptions", json!(["all-unfixed"])),
            ("/report_sha256", json!("bad")),
            ("/counts/High", json!(1)),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(
                receipt(&changed, "gitleaks", "amd64", REV, now()).is_err(),
                "{pointer}"
            );
        }
        let mut changed = value.clone();
        changed["risk"]["private_detail"] = json!("SYNTHETIC_PRIVATE_DIAGNOSTIC");
        assert!(receipt(&changed, "gitleaks", "amd64", REV, now()).is_err());
        let mut changed = value.clone();
        changed["tool"] = json!("syft");
        assert!(receipt(&changed, "syft", "amd64", REV, now()).is_err());
        assert!(risk::inventory(&value, "gitleaks", &sbom()).is_err());
    }

    #[test]
    fn runtime_source_evidence_is_two_architecture_observation_not_approval() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let evidence = read_json(&root.join("licenses/gitleaks-runtime-evidence.json")).unwrap();
        assert_eq!(evidence["schema"], 1);
        assert_eq!(evidence["tool"], "gitleaks");
        assert_eq!(evidence["hosted_run"], 40712836198_u64);
        assert_eq!(
            evidence["source_sha"],
            "818c36229a839653a6952d8079e5952ae51650bc"
        );
        for field in [
            "approval",
            "complete_corresponding_source",
            "complete_notice_coverage",
            "independent_reproducible_build",
            "package_signature_verified",
        ] {
            assert_eq!(evidence[field], false);
        }
        let packages = evidence["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 20);
        let mut identities = BTreeSet::new();
        for record in packages {
            let arch = record["arch"].as_str().unwrap();
            assert!(matches!(arch, "amd64" | "arm64"));
            let package = record["package"].as_str().unwrap();
            assert!(identities.insert((arch, package)));
            for field in [
                "apk_sha256",
                "recipe_sha256",
                "pkginfo_sha256",
                "payload_sha256",
            ] {
                assert!(hex(record[field].as_str().unwrap(), 64));
            }
            assert!(hex(record["recipe_commit"].as_str().unwrap(), 40));
            let url = record["apk_url"].as_str().unwrap();
            assert!(
                url.starts_with("https://apk.cgr.dev/chainguard/")
                    || url.starts_with("https://packages.wolfi.dev/os/")
            );
            assert!(url.ends_with(&format!(
                "/{package}-{}.apk",
                record["version"].as_str().unwrap()
            )));
            assert!(
                record["private_capture"]
                    .as_str()
                    .unwrap()
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            );
        }
        for arch in ["amd64", "arm64"] {
            assert!(hex(evidence["archives"][arch].as_str().unwrap(), 64));
            for package in [
                "git",
                "glibc-2.44",
                "ld-linux-2.44",
                "glibc-2.44-locale-posix",
                "libpcre2-8-0",
                "zlib",
                "libgcc",
                "libstdc++",
                "ca-certificates-bundle",
                "wolfi-baselayout",
            ] {
                assert!(identities.contains(&(arch, package)));
            }
        }
    }

    #[test]
    #[ignore = "approved public APK/recipe captures and run 40712836198 archives; no Docker/network/publication"]
    fn recorded_runtime_recipes_and_original_artifacts_keep_their_hashes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let evidence = read_json(&root.join("licenses/gitleaks-runtime-evidence.json")).unwrap();
        let capture = root.join(".work/approval-suppliers/gitleaks-runtime-v3");
        for record in evidence["packages"].as_array().unwrap() {
            let name = record["private_capture"].as_str().unwrap();
            assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
            let directory = capture.join(name);
            for (file, key) in [
                ("melange.yaml", "recipe_sha256"),
                ("PKGINFO", "pkginfo_sha256"),
            ] {
                assert_eq!(
                    hash(&directory.join(file), 1024 * 1024).unwrap(),
                    record[key]
                );
            }
            assert_eq!(
                hash(
                    &root.join(format!(".work/approval-suppliers/http/{name}.body")),
                    64 * 1024 * 1024
                )
                .unwrap(),
                record["apk_sha256"]
            );
            let files = read_json(&directory.join("files.json")).unwrap();
            assert_eq!(
                files[record["selected_payload"].as_str().unwrap()]["sha256"],
                record["payload_sha256"]
            );
            let image = read_json(
                &capture.join(format!("image-{}.json", record["arch"].as_str().unwrap())),
            )
            .unwrap();
            assert_eq!(
                image[record["shipped_path"].as_str().unwrap()]["sha256"],
                record["payload_sha256"]
            );
        }
        for arch in ["amd64", "arm64"] {
            assert_eq!(
                hash(
                    &root.join(format!(
                        ".work/hosted-40712836198/release-gitleaks-{arch}/gitleaks-{arch}.tar"
                    )),
                    TAR_LIMIT
                )
                .unwrap(),
                evidence["archives"][arch]
            );
        }
    }

    #[test]
    #[ignore = "approved run 40712836198 public handoffs; original-time replay only, no Docker/network/publication"]
    fn hosted_gitleaks_handoffs_pass_content_preflight_not_publication_approval() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join(".work/hosted-40712836198");
        let revision = "818c36229a839653a6952d8079e5952ae51650bc";
        let at = DateTime::parse_from_rfc3339("2026-10-28T15:14:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let fixture = Fixture::new();
        mkdir(&fixture.0.join(".work"), false).unwrap();
        let downloaded = fixture.0.join(".work/downloaded");
        mkdir(&downloaded, false).unwrap();
        for (arch, receipt_hash) in [
            (
                "amd64",
                "1b5b906dda8b2c82063d025f7ab2a46ea474f9edabfea37bfe132e7d9fede502",
            ),
            (
                "arm64",
                "4e990dcfb7a03b08b352294c7d44a86045eff8628896feeaf5dcc34e5eb43f12",
            ),
        ] {
            let directory = format!("release-gitleaks-{arch}");
            let target = downloaded.join(&directory);
            mkdir(&target, false).unwrap();
            let name = format!("gitleaks-{arch}.receipt.json");
            let receipt_path = source.join(&directory).join(&name);
            assert_eq!(hash(&receipt_path, JSON_LIMIT).unwrap(), receipt_hash);
            let receipt = read_json(&receipt_path).unwrap();
            assert_eq!(receipt["source_sha"], revision);
            assert_eq!(receipt["arch"], arch);
            assert_eq!(receipt["status"], "accepted-risk");
            assert_eq!(receipt["count"], 1);
            assert_eq!(receipt["counts"]["Unknown"], 1);
            assert_eq!(receipt["risk"]["accepted"], 1);
            assert_eq!(receipt["risk"]["blocking"], 0);
            for (suffix, key, limit) in [
                ("tar", "tar_sha256", TAR_LIMIT),
                ("syft.json", "sbom_sha256", JSON_LIMIT),
            ] {
                let name = format!("gitleaks-{arch}.{suffix}");
                let path = source.join(&directory).join(&name);
                assert_eq!(hash(&path, limit).unwrap(), receipt[key]);
                fs::copy(path, target.join(name)).unwrap();
            }
            fs::copy(receipt_path, target.join(name)).unwrap();
        }
        let assets = preflight(&fixture.0, &["gitleaks"], revision, at).unwrap();
        assert_eq!(assets.len(), 2);
        assert!(
            assets
                .iter()
                .all(|asset| asset.tool == "gitleaks"
                    && asset.assessment["status"] == "accepted-risk")
        );
        assert_eq!(
            assets
                .iter()
                .map(|asset| asset.arch)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["amd64", "arm64"])
        );
        assert!(publication_readiness(&fixture.0, "gitleaks").is_err());
        assert!(preflight(&fixture.0, &["syft"], revision, at).is_err());
        assert!(preflight(&fixture.0, &["gitleaks"], &"f".repeat(40), at).is_err());
        assert!(
            preflight(
                &fixture.0,
                &["gitleaks"],
                revision,
                at + Duration::hours(25)
            )
            .is_err()
        );
        fs::remove_file(downloaded.join("release-gitleaks-arm64/gitleaks-arm64.tar")).unwrap();
        assert!(preflight(&fixture.0, &["gitleaks"], revision, at).is_err());
    }

    #[test]
    #[ignore = "approved existing Gitleaks dependency-candidate captures only; no Docker/network/publication"]
    fn recorded_gitleaks_candidate_is_accepted_risk_without_removing_its_match() {
        let folder =
            Path::new(env!("CARGO_MANIFEST_DIR")).join(".work/gitleaks-dependency-upgrade");
        let bom_path = folder.join("candidate.syft.json");
        let report_path = folder.join("candidate.grype.json");
        assert_eq!(
            hash(&bom_path, JSON_LIMIT).unwrap(),
            "e30a9ce14a008276c5ff381df9c28af4786c37b6f0a3f21f14b0df3614d2085a"
        );
        assert_eq!(
            hash(&report_path, JSON_LIMIT).unwrap(),
            "5102e0e7cb6969b7d35d1ec883829195d74a3a6549b887143abe9023a27747c5"
        );
        let bom = read_json(&bom_path).unwrap();
        let report = read_json(&report_path).unwrap();
        // Historical replay at the recorded scan time, not a fresh scan claim.
        let at = DateTime::parse_from_rfc3339(text(&report, "/descriptor/timestamp").unwrap())
            .unwrap()
            .with_timezone(&Utc);
        let counts = report_counts(
            &bom,
            &report,
            text(&bom, "/source/metadata/imageID").unwrap(),
            "arm64",
            &report["descriptor"]["db"]["status"],
            at,
        )
        .unwrap();
        assert_eq!(total(&counts), 1);
        assert_eq!(counts["Unknown"], 1);
        let decision = risk::assess("gitleaks", &bom, &report).unwrap();
        assert_eq!(decision["accepted"], 1);
        assert_eq!(decision["blocking"], 0);
        assert_eq!(risk::status(&decision), "accepted-risk");
        assert_eq!(report["matches"].as_array().unwrap().len(), 1);
        // No production inventory/profile change or release receipt is produced.
    }

    #[test]
    #[ignore = "approved fixed Gitleaks candidate SBOM and freshness-validated cache; native offline scan, no publication"]
    fn native_gitleaks_candidate_rescan_retains_accepted_risk() {
        let mut driver = Driver::new().unwrap();
        let input = driver
            .root
            .join(".work/gitleaks-dependency-upgrade/candidate.syft.json");
        assert_eq!(
            hash(&input, JSON_LIMIT).unwrap(),
            "e30a9ce14a008276c5ff381df9c28af4786c37b6f0a3f21f14b0df3614d2085a"
        );
        let bom = read_json(&input).unwrap();
        let packages = sbom_packages(
            &bom,
            "sha256:8af4ca71dde2ef6c5d0254a04ead722208b071ee44c115dde64758f2a6bb338a",
            "arm64",
        )
        .unwrap();
        let cache = mount(&driver.root.join(".work/scans-syft/cache"), "/cache", true).unwrap();
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
        let output = scanner(
            &mut driver,
            GRYPE,
            &["sbom:/input/syft.json", "--output", "json"],
            &[cache, mount(&input, "/input/syft.json", true).unwrap()],
            false,
            0,
        )
        .unwrap();
        let report = read_json(&output).unwrap();
        let counts = super::report_counts(&bom, &packages, &report, &db, Utc::now()).unwrap();
        let decision = risk::assess("gitleaks", &bom, &report).unwrap();
        assert_eq!(total(&counts), 1);
        assert_eq!(decision["accepted"], 1);
        assert_eq!(decision["blocking"], 0);
        assert_eq!(risk::status(&decision), "accepted-risk");
        let diagnostics =
            risk::diagnostics(&super::super::captured_stderr(&output).unwrap()).unwrap();
        write_json(&driver.root.join(".work/gitleaks-accepted-risk-rescan.json"), &json!({
            "scope":"fresh offline scan of retained arm64 candidate inventory; not production adoption or release approval",
            "arch":"arm64","status":"accepted-risk","count":total(&counts),"counts":counts,"risk":decision,"diagnostics":diagnostics,
            "sbom_sha256":hash(&input, JSON_LIMIT).unwrap(),"report_sha256":hash(&output, JSON_LIMIT).unwrap(),"db_built":db["built"]
        })).unwrap();
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
            for tool in TOOLS {
                let dir = downloaded.join(format!("release-{tool}-{arch}"));
                mkdir(&dir, false).unwrap();
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
        // amd64 is now reviewed for real Syft profiles; this unrelated synthetic
        // package still lacks required payload fields and must never pass.
        let coverage = "missing or invalid payload coverage field";
        assert_eq!(
            preflight(&fixture.0, TOOLS, REV, now()).err(),
            Some(coverage)
        );
        let last = downloaded.join("release-docker-arm64/docker-arm64.receipt.json");
        let original = bytes(&last, JSON_LIMIT).unwrap();
        let mut bad: Value = serde_json::from_slice(&original).unwrap();
        bad["count"] = json!(1);
        fs::write(&last, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert_eq!(
            preflight(&fixture.0, TOOLS, REV, now()).err(),
            Some("receipt risk policy or accounting mismatch")
        );
        // A broken Docker handoff is irrelevant to Syft, which still fails its
        // own synthetic coverage (not another tool's finding or missing input).
        assert_eq!(
            preflight(&fixture.0, &["syft"], REV, now()).err(),
            Some(coverage)
        );
        fs::write(&last, &original).unwrap();
        assert!(preflight(&fixture.0, TOOLS, &"f".repeat(40), now()).is_err());
        assert!(preflight(&fixture.0, TOOLS, REV, now() + Duration::hours(25)).is_err());
        let tar = downloaded.join("release-docker-arm64/docker-arm64.tar");
        let original_tar = fs::read(&tar).unwrap();
        fs::write(&tar, b"changed archive").unwrap();
        assert_eq!(
            preflight(&fixture.0, TOOLS, REV, now()).err(),
            Some("downloaded release asset hash mismatch")
        );
        fs::write(&tar, &original_tar).unwrap();
        fs::remove_file(&last).unwrap();
        let error = preflight(&fixture.0, TOOLS, REV, now()).err();
        assert!(error.is_some());
        assert_ne!(error, Some(coverage));
        assert_eq!(
            preflight(&fixture.0, &["syft"], REV, now()).err(),
            Some(coverage)
        );
        write_new(&last, &original, 0o600).unwrap();
        assert_eq!(
            preflight(&fixture.0, TOOLS, REV, now()).err(),
            Some(coverage)
        );
        // All tools keep the two-architecture requirement, independently.
        for tool in TOOLS {
            let path = downloaded.join(format!("release-{tool}-arm64/{tool}-arm64.receipt.json"));
            let original = bytes(&path, JSON_LIMIT).unwrap();
            for field in ["tool", "arch", "source_sha", "tar_sha256", "sbom_sha256"] {
                let mut bad: Value = serde_json::from_slice(&original).unwrap();
                bad[field] = json!("wrong");
                fs::write(&path, bad.to_string()).unwrap();
                assert_eq!(
                    preflight(&fixture.0, &[*tool], REV, now()).err(),
                    Some(if field.ends_with("_sha256") {
                        "malformed receipt hash"
                    } else {
                        "release receipt identity, scanner pin or contract gate mismatch"
                    })
                );
            }
            fs::remove_file(&path).unwrap();
            assert_eq!(
                preflight(&fixture.0, &[*tool], REV, now()).err(),
                Some("cannot open nofollow evidence")
            );
            write_new(&path, &original, 0o600).unwrap();
        }
    }

    #[test]
    #[ignore = "Rust-only subprocess fixture invoked by the diagnostic-scope regression"]
    fn scanner_diagnostic_scope_fixture() {
        let root = PathBuf::from(std::env::var_os("DEVSECOPS_FAKE_ROOT").unwrap());
        let mode = std::env::var("DEVSECOPS_FAKE_CONTRACT").unwrap();
        let mut driver = Driver::new().unwrap();
        let scan = ["sbom:/input/syft.json", "--output", "json"];
        let db = ["db", "status", "--output", "json"];
        for (engine, args, refresh, approved) in [
            (GRYPE, scan.as_slice(), false, true),
            (SYFT, scan.as_slice(), false, false),
            (GRYPE, db.as_slice(), false, false),
            (GRYPE, scan.as_slice(), true, false),
            ("sha256:unreviewed", scan.as_slice(), false, false),
        ] {
            let result = scanner(&mut driver, engine, args, &[], refresh, 0);
            assert_eq!(
                result.is_ok(),
                mode == "empty" || (mode == "precision" && approved)
            );
        }
        let commands = fs::read_to_string(root.join("commands")).unwrap();
        assert_eq!(
            commands
                .lines()
                .filter(|line| line.starts_with("run "))
                .count(),
            5
        );
        assert_eq!(
            commands
                .lines()
                .filter(|line| line.starts_with("rm --force "))
                .count(),
            5
        );
    }

    #[test]
    fn precision_notice_is_scoped_to_pinned_offline_scan_and_cleanup_is_unconditional() {
        let fixture = Fixture::new();
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
        for mode in ["empty", "precision", "precision-extra", "other"] {
            let root = fixture.0.join(mode);
            mkdir(&root, false).unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "release::tests::scanner_diagnostic_scope_fixture",
                    "--ignored",
                    "--nocapture",
                ])
                .env("PATH", &path)
                .env("DEVSECOPS_FAKE_ROOT", &root)
                .env("DEVSECOPS_FAKE_CONTRACT", mode)
                .env_remove("DOCKER_HOST")
                .env_remove("DOCKER_CONTEXT");
            driver.execute(child, 30, false, 0).unwrap();
        }
    }

    #[test]
    fn default_scanner_diagnostics_remain_strict_outside_the_reviewed_scan() {
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
            let output = result.unwrap();
            assert_eq!(output, driver.logs.join(format!("{primary}-stdout.log")));
            assert_eq!(
                risk::diagnostics(&super::super::captured_stderr(&output).unwrap()),
                Ok("go-module-granularity")
            );
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
            let decision = risk::assess(tool, &bom, &report).unwrap();
            assert_eq!(risk::status(&decision), "findings");
            assert_eq!(decision["blocking"].as_u64(), Some(total(&counts)));
            statuses.push(json!({"tool": tool, "status": "blocked-findings", "count": total(&counts), "counts": counts, "risk":decision,"diagnostics":"go-module-granularity", "report_bytes": size}));
        }
        write_json(&driver.root.join(".work/tasks-native-risk-policy-counts.json"), &json!({"scope":"blocked offline candidate capture inspection under reviewed-risk policy, not release acceptance", "arch": arch, "tools": statuses})).unwrap();
    }

    #[test]
    fn syft_subject_validation_rejects_json_diagnostics_before_every_handoff() {
        let clean = sbom();
        assert!(sbom_packages(&clean, &image(), "amd64").is_ok());
        for key in ["error", "errors", "alerts", "warnings"] {
            for empty in [json!([]), json!({}), json!("")] {
                let mut value = clean.clone();
                value[key] = empty;
                assert!(sbom_packages(&value, &image(), "amd64").is_ok());
            }
            for diagnostic in [
                json!(["SYNTHETIC_PRIVATE_DIAGNOSTIC"]),
                json!({"failed":true}),
                json!("analysis failed"),
                Value::Null,
                json!(false),
                json!(1),
            ] {
                let mut value = clean.clone();
                value[key] = diagnostic;
                assert!(sbom_packages(&value, &image(), "amd64").is_err());
            }
        }
        for alerts in [json!([{"failed":true}]), json!({}), Value::Null] {
            let mut value = clean.clone();
            value["alertsByPackage"] = alerts;
            assert!(sbom_packages(&value, &image(), "amd64").is_err());
        }
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
        let mode = std::env::var("DEVSECOPS_FAKE_LOAD").unwrap();
        if ["unapproved-tool", "missing-tool"].contains(&mode.as_str()) {
            assert_eq!(
                publish(&mut driver, "syft"),
                Err("license/source/provenance owner review must approve this exact tool")
            );
            assert!(!root.join("commands").exists());
            return;
        }
        // Real preflight rejects incomplete catalogs. Then exercise the actual
        // post-preflight load AND mutation sequence with synthetic handoffs;
        // deleting its load barrier must make this regression fail.
        assert_eq!(
            publish(&mut driver, "syft"),
            Err("missing or invalid payload coverage field")
        );
        assert!(!root.join("commands").exists());
        let mut assets = Vec::new();
        for arch in ["amd64", "arm64"] {
            for tool in TOOLS {
                let dir = root.join(format!(".work/downloaded/release-{tool}-{arch}"));
                let value = read_json(&dir.join(format!("{tool}-{arch}.receipt.json"))).unwrap();
                assets.push(Asset {
                    tool,
                    arch,
                    image: text(&value, "/image_id").unwrap().to_owned(),
                    config: text(&value, "/config_id").unwrap().to_owned(),
                    tar: dir.join(format!("{tool}-{arch}.tar")),
                    tar_hash: text(&value, "/tar_sha256").unwrap().to_owned(),
                    assessment: public_assessment(&value),
                });
            }
        }
        let single = mode.starts_with("single-");
        let selected = if mode == "single-risk-success" {
            "gitleaks"
        } else {
            "syft"
        };
        if single {
            assets.retain(|asset| asset.tool == selected);
        }
        if mode == "single-risk-success" {
            // A synthetic already-preflighted assessment exercises publication
            // visibility, not scanner/profile acceptance of these fixture bytes.
            for asset in &mut assets {
                asset.assessment["count"] = json!(1);
                asset.assessment["counts"]["Unknown"] = json!(1);
                asset.assessment["status"] = json!("accepted-risk");
                asset.assessment["risk"] = json!({"policy":risk::POLICY,"accepted":1,"blocking":0,"exceptions":["gitleaks-openpgp-no-fix-v1"]});
                risk::receipt(&asset.assessment, selected).unwrap();
            }
        }
        driver.native().unwrap();
        let result = publish_preflighted(
            &mut driver,
            if single {
                std::slice::from_ref(&selected)
            } else {
                TOOLS
            },
            &assets,
            REV,
        );
        let commands = fs::read_to_string(root.join("commands")).unwrap();
        assert_eq!(
            commands
                .lines()
                .filter(|line| line.starts_with("image load "))
                .count(),
            if single { 2 } else { 18 }
        );
        if mode.ends_with("success") {
            result.unwrap();
            assert_eq!(
                commands
                    .lines()
                    .filter(|line| line.starts_with("image push "))
                    .count(),
                2
            );
            assert_eq!(
                commands
                    .lines()
                    .filter(|line| line.starts_with("image tag "))
                    .count(),
                2
            );
            assert!(!commands.contains("ghcr.io/prjxai/devsecops/docker"));
            let published = root.join(format!(".work/published-{selected}"));
            let subjects = fs::read_to_string(published.join("subjects.checksums")).unwrap();
            assert_eq!(subjects.lines().count(), 1);
            assert!(subjects.ends_with(&format!("  ghcr.io/prjxai/devsecops/{selected}\n")));
            assert!(!root.join(".work/published-docker").exists());
            let status = read_json(&published.join("release-status.json")).unwrap();
            assert_eq!(status["source_sha"], REV);
            assert_eq!(status["tool"], selected);
            assert_eq!(
                status["manifest_digest"],
                fs::read_to_string(root.join("registry-index.id")).unwrap()
            );
            assert_eq!(
                status["status"],
                if selected == "gitleaks" {
                    "accepted-risk"
                } else {
                    "clean"
                }
            );
            let architectures = status["architectures"].as_array().unwrap();
            assert_eq!(architectures.len(), 2);
            for assessment in architectures {
                assert_eq!(assessment["count"], u64::from(selected == "gitleaks"));
                assert_eq!(assessment["status"], status["status"]);
                risk::receipt(assessment, selected).unwrap();
            }
        } else {
            assert!(result.is_err());
            assert!(
                !commands
                    .lines()
                    .any(|line| line.starts_with("image push ") || line.starts_with("image tag "))
            );
        }
    }

    #[test]
    fn independent_success_and_bad_second_or_eighteenth_loads_preserve_the_push_barrier() {
        let fixture = Fixture::new();
        let github = fixture.0.join(".github");
        fs::create_dir_all(github.join("publication-readiness")).unwrap();
        write_json(&github.join("publication-readiness/syft.json"), &json!({"schema":2,"tool":"syft","repository":"ghcr.io/prjxai/devsecops/syft","redistribution_complete":true,"supplier_provenance_reviewed":true,"native_functional_contracts_complete":true,"blockers":[]})).unwrap();
        let work = fixture.0.join(".work");
        mkdir(&work, false).unwrap();
        let downloaded = work.join("downloaded");
        mkdir(&downloaded, false).unwrap();
        for arch in ["amd64", "arm64"] {
            let id = format!(
                "sha256:{}",
                if arch == "amd64" { "a" } else { "b" }.repeat(64)
            );
            for tool in TOOLS {
                let dir = downloaded.join(format!("release-{tool}-{arch}"));
                mkdir(&dir, false).unwrap();
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
        // Fake registry bytes are hash-bound exactly like real registry responses.
        // This exercises only the post-preflight sequence, never scan acceptance.
        let mut manifests = Vec::new();
        for arch in ["amd64", "arm64"] {
            let value = read_json(
                &downloaded.join(format!("release-syft-{arch}/syft-{arch}.receipt.json")),
            )
            .unwrap();
            let manifest = json!({"schemaVersion":2,"config":{"digest":value["config_id"]},"layers":[{"digest":image()}]});
            let data = serde_json::to_vec(&manifest).unwrap();
            let path = fixture.0.join(format!("registry-{arch}.json"));
            write_new(&path, &data, 0o600).unwrap();
            let digest = format!("sha256:{}", hash(&path, JSON_LIMIT).unwrap());
            write_new(
                &fixture.0.join(format!("registry-{arch}.id")),
                digest.as_bytes(),
                0o600,
            )
            .unwrap();
            manifests.push(json!({"digest":digest,"platform":{"architecture":arch,"os":"linux"}}));
        }
        let data = serde_json::to_vec(&json!({"schemaVersion":2,"manifests":manifests})).unwrap();
        write_new(&fixture.0.join("registry-index.json"), &data, 0o600).unwrap();
        write_new(
            &fixture.0.join("registry-index.id"),
            format!(
                "sha256:{}",
                hash(&fixture.0.join("registry-index.json"), JSON_LIMIT).unwrap()
            )
            .as_bytes(),
            0o600,
        )
        .unwrap();
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
        for mode in [
            "unapproved-tool",
            "missing-tool",
            "wrong",
            "multiple",
            "malformed",
            "single-wrong",
            "single-multiple",
            "single-malformed",
            "single-success",
            "single-risk-success",
        ] {
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
                .env(
                    "DEVSECOPS_LICENSE_SOURCE_PROVENANCE_APPROVED_TOOL",
                    match mode {
                        "unapproved-tool" => "grype",
                        "missing-tool" => "",
                        _ => "syft",
                    },
                )
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
            .docker_archive(&["image", "save", &image], &archive)
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
        for (tool, file, expected) in [
            (
                "kind",
                "kind/LICENSE",
                "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1",
            ),
            (
                "kustomize",
                "kustomize/LICENSE",
                "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1",
            ),
            (
                "kubectl",
                "kubectl/LICENSE",
                "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
            ),
            (
                "docker",
                "docker/LICENSE",
                "2d81ea060825006fc8f3fe28aa5dc0ffeb80faf325b612c955229157b8c10dc0",
            ),
            (
                "docker",
                "docker/NOTICE",
                "a8c869fbda819afb8d80e0ac19bac52e766bc6c19cb38cf94f52d64c4be2aab6",
            ),
            (
                "docker",
                "compose/LICENSE",
                "58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd",
            ),
            (
                "docker",
                "compose/NOTICE",
                "b7dca0a6b01fa7365e4892877a6321179ee343d72ee87a96cfc222141b99a1e6",
            ),
            (
                "docker",
                "buildx/LICENSE",
                "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
            ),
            (
                "kind",
                "docker/LICENSE",
                "2d81ea060825006fc8f3fe28aa5dc0ffeb80faf325b612c955229157b8c10dc0",
            ),
            (
                "kind",
                "docker/NOTICE",
                "a8c869fbda819afb8d80e0ac19bac52e766bc6c19cb38cf94f52d64c4be2aab6",
            ),
        ] {
            let image = driver.check(tool).unwrap();
            let name = format!(
                "license-{}-{}",
                driver.logs.file_name().unwrap().to_str().unwrap(),
                tool
            );
            let destination = driver.logs.join(format!("notice-{}", driver.sequence));
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
                        &format!("{name}:/usr/share/licenses/{file}"),
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
