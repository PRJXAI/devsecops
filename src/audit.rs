//! First-party Cargo.lock gate and native cargo-audit controls. Retrieval is public
//! and separate from offline analysis; provider output never enters public evidence.
//! A receipt proves retrieval time, not advisory commit age (quiet databases are valid).
//! Like the release handoff, this trusts the private runner's same-UID filesystem.

use super::{Driver, Result, release};
use chrono::{DateTime, Duration, Utc};
use rustix::fs::{Mode, OFlags, open};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::Ordering,
};

const SOURCE: &str = "https://github.com/RustSec/advisory-db";
const LIMIT: u64 = 8 * 1024 * 1024;
const DB_LIMIT: u64 = 512 * 1024 * 1024;
const CLEAN: &str = "version = 4\n\n[[package]]\nname = \"synthetic-clean\"\nversion = \"0.0.0\"\n";
const VULNERABLE: &str = "version = 4\n\n[[package]]\nname = \"synthetic-vulnerable\"\nversion = \"0.0.0\"\ndependencies = [\"time\"]\n\n[[package]]\nname = \"time\"\nversion = \"0.1.43\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";

fn mkdir(path: &Path, mode: u32) -> Result<()> {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "cannot create private audit directory")?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| "cannot secure audit directory")
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "cannot create audit evidence")?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "cannot write audit evidence")?;
    // Set explicitly, including under umask 077. Only mounted input leaves are shared.
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| "cannot secure audit evidence")
}

fn next(driver: &mut Driver) -> Result<u32> {
    driver.sequence = driver
        .sequence
        .checked_add(1)
        .ok_or("audit sequence exhausted")?;
    Ok(driver.sequence)
}

fn input(driver: &mut Driver) -> Result<PathBuf> {
    let sequence = next(driver)?;
    let parent = driver.logs.join(format!("audit-input-{sequence}"));
    mkdir(&parent, 0o700)?;
    let leaf = parent.join("input");
    mkdir(&leaf, 0o755)?;
    Ok(leaf)
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or("invalid audit evidence")
}

// Git inherits neither operator config nor credentials/proxies/URL rewrites. No
// shell, askpass helper, template hook, submodule, redirect or alternate URL.
fn git(driver: &mut Driver, parent: &Path, args: &[&str]) -> Result<PathBuf> {
    let mut command = Command::new("git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HOME", parent)
        .env("XDG_CONFIG_HOME", parent)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/dev/null")
        .env("SSH_ASKPASS", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .args([
            "--no-optional-locks",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "credential.helper=",
            "-c",
            "credential.interactive=false",
            "-c",
            "init.templateDir=",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.sslVerify=true",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
        ])
        .args(args)
        .current_dir(parent);
    driver
        .execute(command, 180, false, 0)
        .map_err(|_| "RustSec retrieval or verification failed; private logs retained")
}

fn commit(driver: &mut Driver, parent: &Path, db: &Path) -> Result<String> {
    let db = db.to_str().ok_or("invalid private RustSec path")?;
    let output = git(
        driver,
        parent,
        &["-C", db, "rev-parse", "--verify", "HEAD^{commit}"],
    )?;
    let data = release::bytes(&output, 128).map_err(|_| "invalid RustSec commit evidence")?;
    let value = std::str::from_utf8(&data)
        .map_err(|_| "invalid RustSec commit evidence")?
        .trim();
    if !hex(value, 40) {
        return Err("invalid RustSec commit evidence");
    }
    Ok(value.to_owned())
}

// Bound and hash the entire private checkout (including Git metadata), reject
// links/special files, and seal readable input modes. The parent remains 0700.
// These bounds detect oversized retrieval after clone; they are not a disk quota.
fn tree(db: &Path, seal: bool) -> Result<(String, u64)> {
    let mut pending = vec![db.to_path_buf()];
    let mut entries = Vec::new();
    while let Some(path) = pending.pop() {
        if entries.len() + pending.len() >= 100_000 {
            return Err("RustSec database entry limit exceeded");
        }
        let meta = fs::symlink_metadata(&path).map_err(|_| "cannot inspect RustSec database")?;
        if meta.is_dir() {
            for entry in fs::read_dir(&path).map_err(|_| "cannot read RustSec database")? {
                pending.push(entry.map_err(|_| "cannot read RustSec database")?.path());
                if entries.len() + pending.len() >= 100_000 {
                    return Err("RustSec database entry limit exceeded");
                }
            }
            if seal {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o555))
                    .map_err(|_| "cannot seal RustSec database")?;
            } else if meta.permissions().mode() & 0o555 != 0o555 {
                return Err("RustSec database is not readable by scanner identity");
            }
        } else if !meta.is_file() {
            return Err("RustSec database contains unsupported file types");
        }
        entries.push(path);
    }
    entries.sort();
    let (mut total, mut advisories) = (0u64, 0u64);
    let mut hash = Sha256::new();
    for path in entries {
        let meta = fs::symlink_metadata(&path).map_err(|_| "cannot inspect RustSec database")?;
        if !meta.is_file() {
            continue;
        }
        let relative = path
            .strip_prefix(db)
            .map_err(|_| "invalid RustSec input path")?;
        let name = relative.to_str().ok_or("invalid RustSec input path")?;
        if name.starts_with("crates/")
            && name.ends_with(".md")
            && name.contains("/RUSTSEC-")
            && meta.len() > 0
        {
            advisories += 1;
        }
        // Git packfiles may exceed the report limit, but never the tree budget.
        let data = read_allow_empty(&path, 64 * 1024 * 1024)?;
        total = total
            .checked_add(data.len() as u64)
            .ok_or("RustSec database size exceeded")?;
        if total > DB_LIMIT {
            return Err("RustSec database size exceeded");
        }
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update((data.len() as u64).to_be_bytes());
        hash.update(&data);
        if seal {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o444))
                .map_err(|_| "cannot seal RustSec database")?;
        } else if meta.permissions().mode() & 0o444 != 0o444 {
            return Err("RustSec database is not readable by scanner identity");
        }
    }
    if advisories == 0 {
        return Err("RustSec database contains no advisories");
    }
    Ok((
        hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
        advisories,
    ))
}

fn read_allow_empty(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "cannot open private audit evidence")?;
    let file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|_| "cannot inspect private audit evidence")?;
    if !meta.is_file() || meta.len() > limit {
        return Err("invalid private audit evidence size or type");
    }
    let mut data = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| "cannot read private audit evidence")?;
    if data.len() as u64 > limit {
        return Err("private audit evidence size exceeded");
    }
    Ok(data)
}

struct Database {
    path: PathBuf,
    commit: String,
}

fn receipt(value: &Value, identity: &str, now: DateTime<Utc>) -> Result<()> {
    if value["schema"] != 1
        || field(value, "source")? != SOURCE
        || field(value, "driver")? != identity
        || !hex(field(value, "commit")?, 40)
        || !hex(field(value, "tree_sha256")?, 64)
        || value["advisory_files"].as_u64().is_none_or(|n| n == 0)
    {
        return Err("invalid RustSec retrieval receipt");
    }
    let retrieved = DateTime::parse_from_rfc3339(field(value, "retrieved")?)
        .map_err(|_| "invalid RustSec retrieval timestamp")?;
    let age = now.signed_duration_since(retrieved);
    if age < Duration::zero() || age > Duration::hours(24) {
        return Err("stale or future RustSec retrieval receipt");
    }
    Ok(())
}

fn database(driver: &mut Driver) -> Result<Database> {
    // logs is unique to this Driver; no cross-driver/cross-job cache or fallback.
    let parent = driver.logs.join("audit-db");
    let db = parent.join("database");
    let identity = driver
        .logs
        .to_str()
        .ok_or("invalid audit driver identity")?
        .to_owned();
    match fs::symlink_metadata(&parent) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            mkdir(&parent, 0o700)?;
            let dest = db.to_str().ok_or("invalid private RustSec path")?;
            git(
                driver,
                &parent,
                &[
                    "clone",
                    "--depth=1",
                    "--single-branch",
                    "--no-tags",
                    "--template=",
                    "--origin=public",
                    "--",
                    SOURCE,
                    dest,
                ],
            )?;
            let revision = commit(driver, &parent, &db)?;
            let (hash, advisories) = tree(&db, true)?;
            let value = json!({"schema":1,"source":SOURCE,"driver":identity,"commit":revision,
                "tree_sha256":hash,"advisory_files":advisories,"retrieved":Utc::now().to_rfc3339()});
            write_new(
                &parent.join("receipt.json"),
                value.to_string().as_bytes(),
                0o600,
            )?;
        }
        Ok(meta) if meta.is_dir() && meta.permissions().mode() & 0o777 == 0o700 => (),
        _ => return Err("invalid private RustSec retrieval directory"),
    }
    let data = release::bytes(&parent.join("receipt.json"), 4096)
        .map_err(|_| "missing or invalid RustSec retrieval receipt")?;
    let value: Value =
        serde_json::from_slice(&data).map_err(|_| "invalid RustSec retrieval receipt")?;
    receipt(&value, &identity, Utc::now())?;
    let (hash, advisories) = tree(&db, false)?;
    if hash != field(&value, "tree_sha256")? || value["advisory_files"].as_u64() != Some(advisories)
    {
        return Err("RustSec database differs from retrieval receipt");
    }
    // Validate the tree before Git can read its local configuration.
    let revision = commit(driver, &parent, &db)?;
    if revision != field(&value, "commit")? {
        return Err("RustSec commit differs from retrieval receipt");
    }
    Ok(Database {
        path: db,
        commit: revision,
    })
}

fn mount(path: &Path, target: &str) -> Result<String> {
    if !path.is_absolute()
        || !fs::symlink_metadata(path)
            .map_err(|_| "missing audit input")?
            .is_dir()
    {
        return Err("audit input must be an absolute nonsymlink directory");
    }
    let source = path
        .to_str()
        .filter(|p| !p.contains([',', '\n', '\r']))
        .ok_or("invalid audit input mount")?;
    Ok(format!(
        "type=bind,source={source},target={target},readonly"
    ))
}

fn run(
    driver: &mut Driver,
    image: &str,
    input: &Path,
    db: Option<&Database>,
    expected: i32,
) -> Result<PathBuf> {
    if !image.strip_prefix("sha256:").is_some_and(|v| hex(v, 64)) {
        return Err("cargo-audit requires an immutable checked image ID");
    }
    let identity = driver
        .logs
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("invalid audit run identity")?;
    let name = format!("audit-{identity}-{}", driver.sequence);
    let platform = match std::env::consts::ARCH {
        "x86_64" => "--platform=linux/amd64",
        "aarch64" => "--platform=linux/arm64",
        _ => return Err("unsupported native audit architecture"),
    };
    let input_mount = mount(input, "/input")?;
    let db_mount = db.map(|db| mount(&db.path, "/rustsec")).transpose()?;
    let mut args = vec![
        "run",
        "--pull=never",
        platform,
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
        "--env=CARGO_HOME=/tmp/cargo",
        "--env=XDG_CONFIG_HOME=/tmp/config",
        "--env=XDG_CACHE_HOME=/tmp/cache",
        "--mount",
        &input_mount,
    ];
    if let Some(db_mount) = &db_mount {
        args.extend(["--mount", db_mount]);
    }
    args.extend([
        image,
        "--no-fetch",
        "--stale",
        "--db",
        if db.is_some() {
            "/rustsec"
        } else {
            "/missing-rustsec"
        },
        "--file",
        "/input/Cargo.lock",
        "--json",
    ]);
    // --stale disables the tool's commit-age heuristic, NOT our <=24h retrieval
    // receipt gate. A newly retrieved quiet repository is meaningful fresh data.
    let result = driver.docker_exit(&args, 180, false, expected);
    // Always bounded, even on spawn errors, timeout, overflow and cancellation.
    let cleanup = driver.docker_exit(&["rm", "--force", &name], 15, true, 0);
    match (result, cleanup) {
        (_, Err(_)) => Err("cargo-audit container cleanup was not confirmed"),
        (Err(_), Ok(_)) => Err("cargo-audit execution failed; private logs retained"),
        (Ok(_), Ok(_)) if driver.cancelled.load(Ordering::Relaxed) => Err("audit cancelled"),
        (Ok(path), Ok(_)) => Ok(path),
    }
}

#[derive(Debug)]
struct Lock {
    packages: BTreeSet<(String, String)>,
    count: u64,
}

// Deliberately narrow reader for Cargo-generated lockfiles, not a TOML engine.
// Cargo-audit independently parses the exact same copied bytes. Unsupported
// package field syntax fails closed rather than weakening the coverage check.
fn lock(data: &[u8]) -> Result<Lock> {
    let text = std::str::from_utf8(data).map_err(|_| "invalid audit lockfile")?;
    let mut packages = BTreeSet::new();
    let (mut count, mut name, mut version) = (0u64, None, None);
    let mut active = false;
    let mut finish = |name: &mut Option<String>, version: &mut Option<String>| -> Result<()> {
        packages.insert((
            name.take().ok_or("missing lock package name")?,
            version.take().ok_or("missing lock package version")?,
        ));
        Ok(())
    };
    for line in text.lines().map(str::trim) {
        if line == "[[package]]" {
            if active {
                finish(&mut name, &mut version)?;
            }
            active = true;
            count += 1;
        } else if line.starts_with('[') && !line.starts_with("[\"") && line != "]" {
            return Err("unsupported audit lockfile table");
        } else if active && let Some((key, value)) = line.split_once('=') {
            let target = match key.trim() {
                "name" => Some(&mut name),
                "version" => Some(&mut version),
                _ => None,
            };
            if let Some(target) = target {
                let value: String = serde_json::from_str(value.trim())
                    .map_err(|_| "unsupported lock package field")?;
                if target.is_some() || value.is_empty() {
                    return Err("invalid lock package identity");
                }
                *target = Some(value);
            }
        }
    }
    if active {
        finish(&mut name, &mut version)?;
    }
    if count == 0 {
        return Err("empty audit lockfile coverage");
    }
    Ok(Lock { packages, count })
}

#[derive(Debug, PartialEq)]
struct Counts {
    vulnerabilities: u64,
    warnings: u64,
}

fn parse(data: &[u8], lock: &Lock, revision: &str, vulnerable_control: bool) -> Result<Counts> {
    if data.len() as u64 > LIMIT {
        return Err("audit report size exceeded");
    }
    let value: Value = serde_json::from_slice(data).map_err(|_| "malformed cargo-audit report")?;
    for key in ["error", "errors"] {
        if value.get(key).is_some() {
            return Err("cargo-audit reported an analysis error");
        }
    }
    if value.as_object().is_none_or(|m| m.len() != 5) {
        return Err("unsupported cargo-audit report schema");
    }
    // The pinned --no-fetch presenter emits null Git metadata. Identity is
    // independently bound by the verified checkout hash and retrieval receipt.
    let db = &value["database"];
    if db["advisory-count"].as_u64().is_none_or(|n| n == 0)
        || (db.get("last-commit") != Some(&Value::Null)
            && db["last-commit"].as_str() != Some(revision))
        || value["lockfile"]["dependency-count"].as_u64() != Some(lock.count)
    {
        return Err("cargo-audit database or lockfile coverage mismatch");
    }
    let settings = value["settings"]
        .as_object()
        .ok_or("missing cargo-audit settings")?;
    if settings.len() != 5
        || settings
            .get("ignore")
            .and_then(Value::as_array)
            .is_none_or(|a| !a.is_empty())
        || ["target_arch", "target_os"].iter().any(|k| {
            settings
                .get(*k)
                .and_then(Value::as_array)
                .is_none_or(|a| !a.is_empty())
        })
        || settings.get("severity") != Some(&Value::Null)
    {
        return Err("cargo-audit ignored or filtered coverage");
    }
    let informational = settings
        .get("informational_warnings")
        .and_then(Value::as_array)
        .ok_or("missing cargo-audit warning coverage")?;
    if informational.len() != 3
        || !["unmaintained", "unsound", "notice"]
            .iter()
            .all(|kind| informational.iter().any(|v| v.as_str() == Some(kind)))
    {
        return Err("incomplete cargo-audit warning coverage");
    }
    let vulnerabilities = &value["vulnerabilities"];
    let list = vulnerabilities["list"]
        .as_array()
        .ok_or("missing cargo-audit vulnerability list")?;
    let count = vulnerabilities["count"]
        .as_u64()
        .ok_or("invalid cargo-audit vulnerability count")?;
    if count != list.len() as u64 || vulnerabilities["found"].as_bool() != Some(count > 0) {
        return Err("inconsistent cargo-audit vulnerability evidence");
    }
    let mut seeded = false;
    for item in list {
        let package = &item["package"];
        let name = field(package, "name")?;
        let version = field(package, "version")?;
        let advisory = &item["advisory"];
        let id = field(advisory, "id")?;
        if !lock
            .packages
            .contains(&(name.to_owned(), version.to_owned()))
            || advisory["package"].as_str() != Some(name)
            || !id.strip_prefix("RUSTSEC-").is_some_and(|s| {
                s.len() == 9
                    && s.as_bytes()[4] == b'-'
                    && s.bytes()
                        .enumerate()
                        .all(|(i, b)| i == 4 || b.is_ascii_digit())
            })
        {
            return Err("invalid cargo-audit finding identity");
        }
        seeded |= name == "time" && version == "0.1.43" && id == "RUSTSEC-2020-0071";
    }
    if vulnerable_control && !seeded {
        return Err("cargo-audit missed the seeded time advisory");
    }
    let warnings = value["warnings"]
        .as_object()
        .ok_or("missing cargo-audit warnings")?;
    let mut warning_count = 0u64;
    for items in warnings.values() {
        warning_count += items
            .as_array()
            .ok_or("malformed cargo-audit warning list")?
            .len() as u64;
    }
    Ok(Counts {
        vulnerabilities: count,
        warnings: warning_count,
    })
}

fn report(stdout: &Path, lock: &Lock, db: &Database, vulnerable: bool) -> Result<Counts> {
    let counts = parse(
        &release::bytes(stdout, LIMIT)?,
        lock,
        &db.commit,
        vulnerable,
    )?;
    // JSON warnings are checked separately. Unexpected stderr is never evidence
    // of a clean audit, even when the tool returns zero and emits plausible JSON.
    if !super::captured_stderr(stdout)?
        .iter()
        .all(u8::is_ascii_whitespace)
    {
        return Err("cargo-audit emitted diagnostics; private logs retained");
    }
    Ok(counts)
}

fn missing_database(data: &[u8], diagnostics: &[u8]) -> Result<()> {
    // A runtime failure or malformed finding JSON must not satisfy this control.
    // Match only the pinned tool's missing-input diagnostic, kept private.
    if !data.iter().all(u8::is_ascii_whitespace) {
        return Err("unexpected missing-database report");
    }
    let text = std::str::from_utf8(diagnostics).map_err(|_| "invalid missing-database evidence")?;
    if !text.contains("advisory database")
        || !text.contains("/missing-rustsec")
        || !text.contains("No such file or directory")
    {
        return Err("missing-database failure was not identified");
    }
    Ok(())
}

/// Native offline clean/vulnerable/missing-DB controls; only synthetic lockfiles.
pub(super) fn contract(driver: &mut Driver, image: &str) -> Result<()> {
    let (arch, _) = driver.native()?;
    if driver.inspect(image, arch)? != image {
        return Err("cargo-audit native image identity mismatch");
    }
    let db = database(driver)?;
    let clean = input(driver)?;
    write_new(&clean.join("Cargo.lock"), CLEAN.as_bytes(), 0o444)?;
    let output = run(driver, image, &clean, Some(&db), 0)?;
    if report(&output, &lock(CLEAN.as_bytes())?, &db, false)?
        != (Counts {
            vulnerabilities: 0,
            warnings: 0,
        })
    {
        return Err("cargo-audit clean control had findings or warnings");
    }
    let vulnerable = input(driver)?;
    write_new(&vulnerable.join("Cargo.lock"), VULNERABLE.as_bytes(), 0o444)?;
    let output = run(driver, image, &vulnerable, Some(&db), 1)?;
    let counts = report(&output, &lock(VULNERABLE.as_bytes())?, &db, true)?;
    if counts.vulnerabilities == 0 {
        return Err("cargo-audit vulnerable control was clean");
    }
    let output = run(driver, image, &clean, None, 1)?;
    missing_database(
        &read_allow_empty(&output, LIMIT)?,
        &super::captured_stderr(&output)?,
    )
}

fn summary(driver: &mut Driver, status: &str, counts: Option<&Counts>) -> Result<()> {
    let value = json!({"status":status,"vulnerabilities":counts.map(|c| c.vulnerabilities),"warnings":counts.map(|c| c.warnings)});
    let sequence = next(driver)?;
    let temp = driver.logs.join(format!("audit-summary-{sequence}.json"));
    write_new(&temp, value.to_string().as_bytes(), 0o600)?;
    // Replaces any old clean summary before work starts. Never follows a leaf
    // symlink or copies any provider fields into public evidence.
    fs::rename(temp, driver.root.join(".work/public-audit.json"))
        .map_err(|_| "cannot publish counts-only audit status")
}

/// Build/check the pinned packaged tool, prove its controls, then audit this repo.
/// A nonzero exit or any parse/coverage/DB/diagnostic error blocks the gate.
pub(super) fn gate(driver: &mut Driver) -> Result<()> {
    summary(driver, "error", None)?;
    let result = (|| {
        let image = driver.check("cargo-audit")?;
        contract(driver, &image)?;
        let db = database(driver)?;
        let bytes = release::bytes(&driver.root.join("Cargo.lock"), LIMIT)
            .map_err(|_| "cannot read repository audit lockfile")?;
        let lock = lock(&bytes)?;
        let input = input(driver)?;
        write_new(&input.join("Cargo.lock"), &bytes, 0o444)?;
        let output = run(driver, &image, &input, Some(&db), 0)?;
        let counts = report(&output, &lock, &db, false)?;
        let clean = counts.vulnerabilities == 0 && counts.warnings == 0;
        summary(
            driver,
            if clean { "clean" } else { "findings" },
            Some(&counts),
        )?;
        if clean {
            Ok(())
        } else {
            Err("repository dependency audit has findings or warnings")
        }
    })();
    result
        .map_err(|_| "repository dependency audit blocked; see counts-only status and private logs")
}

#[cfg(test)]
mod tests {
    use super::*;

    const REV: &str = "0123456789abcdef0123456789abcdef01234567";
    const SENSITIVE: &str = "SYNTHETIC_PRIVATE_DIAGNOSTIC_NEVER_PUBLIC";

    fn evidence(vulnerable: bool) -> Value {
        json!({"database":{"advisory-count":1,"last-commit":REV,"last-updated":"2001-01-01T00:00:00Z"},
            "lockfile":{"dependency-count":if vulnerable {2} else {1}},
            "settings":{"target_arch":[],"target_os":[],"severity":null,"ignore":[],"informational_warnings":["unmaintained","unsound","notice"]},
            "vulnerabilities":{"found":vulnerable,"count":if vulnerable {1} else {0},"list":if vulnerable {json!([{"advisory":{"id":"RUSTSEC-2020-0071","package":"time"},"package":{"name":"time","version":"0.1.43"}}])} else {json!([])}},"warnings":{}})
    }

    fn parse_value(value: &Value, vulnerable: bool) -> Result<Counts> {
        parse(
            &serde_json::to_vec(value).unwrap(),
            &lock(if vulnerable {
                VULNERABLE.as_bytes()
            } else {
                CLEAN.as_bytes()
            })
            .unwrap(),
            REV,
            vulnerable,
        )
    }

    #[test]
    fn parser_accepts_clean_and_identified_vulnerable_controls() {
        assert_eq!(
            parse_value(&evidence(false), false).unwrap(),
            Counts {
                vulnerabilities: 0,
                warnings: 0
            }
        );
        assert_eq!(
            parse_value(&evidence(true), true).unwrap().vulnerabilities,
            1
        );
    }

    #[test]
    fn parser_refuses_missing_db_coverage_filters_and_inconsistent_findings() {
        for (pointer, replacement) in [
            ("/database/advisory-count", json!(0)),
            ("/database/last-commit", json!("f".repeat(40))),
            ("/lockfile/dependency-count", json!(0)),
            ("/settings/ignore", json!(["RUSTSEC-2020-0071"])),
            ("/settings/target_arch", json!("aarch64")),
            ("/settings/target_os", json!("linux")),
            ("/settings/severity", json!("critical")),
            ("/settings/informational_warnings", json!([])),
            ("/vulnerabilities/count", json!(0)),
            ("/vulnerabilities/found", json!(false)),
            ("/vulnerabilities/list", json!([])),
            (
                "/vulnerabilities/list/0/advisory/id",
                json!("RUSTSEC-9999-9999"),
            ),
            ("/vulnerabilities/list/0/package/version", json!("0.1.44")),
            ("/vulnerabilities/list/0/advisory/package", json!("other")),
            ("/warnings", Value::Null),
        ] {
            let mut bad = evidence(true);
            *bad.pointer_mut(pointer).unwrap() = replacement;
            assert!(parse_value(&bad, true).is_err(), "{pointer}");
        }
        for key in [
            "database",
            "settings",
            "lockfile",
            "vulnerabilities",
            "warnings",
        ] {
            let mut bad = evidence(false);
            bad.as_object_mut().unwrap().remove(key);
            assert!(parse_value(&bad, false).is_err());
        }
    }

    #[test]
    fn warnings_are_counts_not_clean_and_diagnostics_stay_generic() {
        let mut warning = evidence(false);
        warning["warnings"] = json!({"unmaintained":[{"message":SENSITIVE}]});
        assert_eq!(parse_value(&warning, false).unwrap().warnings, 1);
        warning["error"] = json!(SENSITIVE);
        let error = parse_value(&warning, false).unwrap_err();
        assert!(!error.contains(SENSITIVE));
        for data in [SENSITIVE.as_bytes(), b"{truncated", b"{}", b"null"] {
            let error = parse(data, &lock(CLEAN.as_bytes()).unwrap(), REV, false).unwrap_err();
            assert!(!error.contains(SENSITIVE));
        }
        assert!(missing_database(b"{}", SENSITIVE.as_bytes()).is_err());
        assert!(missing_database(b"", SENSITIVE.as_bytes()).is_err());
        assert!(
            missing_database(
                b"{truncated",
                b"advisory database /missing-rustsec No such file or directory"
            )
            .is_err()
        );
        assert!(
            missing_database(
                b"",
                b"advisory database /missing-rustsec No such file or directory"
            )
            .is_ok()
        );
    }

    #[test]
    fn retrieval_freshness_is_not_commit_recency_and_never_falls_back() {
        let now = Utc::now();
        let good = json!({"schema":1,"source":SOURCE,"driver":"same-driver","commit":REV,"tree_sha256":"a".repeat(64),"advisory_files":1,"retrieved":now.to_rfc3339()});
        assert!(receipt(&good, "same-driver", now).is_ok());
        assert!(receipt(&good, "other-driver", now).is_err());
        for value in [
            json!((now - Duration::hours(24) - Duration::seconds(1)).to_rfc3339()),
            json!((now + Duration::seconds(1)).to_rfc3339()),
            json!(SENSITIVE),
            Value::Null,
        ] {
            let mut bad = good.clone();
            bad["retrieved"] = value;
            assert!(receipt(&bad, "same-driver", now).is_err());
        }
        assert!(receipt(&good, "same-driver", now + Duration::hours(24)).is_ok());
        for (key, value) in [
            ("commit", json!("short")),
            ("tree_sha256", Value::Null),
            ("advisory_files", json!(0)),
            ("source", json!("https://example.invalid")),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(receipt(&bad, "same-driver", now).is_err());
        }
        // An old last-updated commit with a newly retrieved receipt is accepted.
        assert!(parse_value(&evidence(false), false).is_ok());
    }

    #[test]
    fn lock_coverage_rejects_empty_incomplete_or_unsupported_package_tables() {
        assert_eq!(lock(CLEAN.as_bytes()).unwrap().count, 1);
        assert_eq!(lock(VULNERABLE.as_bytes()).unwrap().count, 2);
        for bad in [
            "",
            "version = 4",
            "[[package]]\nname = \"x\"",
            "[[patch.unused]]",
            "[[package]]\nname = 'x'\nversion = '1'",
        ] {
            assert!(lock(bad.as_bytes()).is_err());
        }
    }

    #[test]
    fn private_inputs_public_counts_and_cache_fail_closed_without_network() {
        let mut driver = Driver::new().unwrap();
        let input = input(&mut driver).unwrap();
        write_new(&input.join("Cargo.lock"), CLEAN.as_bytes(), 0o444).unwrap();
        assert_eq!(
            fs::metadata(&input).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(input.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(input.join("Cargo.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        let parent = driver.logs.join("audit-db");
        mkdir(&parent, 0o700).unwrap();
        let sequence = driver.sequence;
        assert!(database(&mut driver).is_err()); // partial retrieval is not retried
        assert_eq!(sequence, driver.sequence);
        // Isolate summary from other test/process instances' real public status.
        driver.root = driver.logs.clone();
        mkdir(&driver.root.join(".work"), 0o700).unwrap();
        summary(
            &mut driver,
            "clean",
            Some(&Counts {
                vulnerabilities: 0,
                warnings: 0,
            }),
        )
        .unwrap();
        summary(&mut driver, "error", None).unwrap();
        let public = fs::read_to_string(driver.root.join(".work/public-audit.json")).unwrap();
        let value: Value = serde_json::from_str(&public).unwrap();
        assert_eq!(
            value,
            json!({"status":"error","vulnerabilities":null,"warnings":null})
        );
        assert!(!public.contains(SENSITIVE));
        assert!(!public.contains(SOURCE));
    }

    #[test]
    fn empty_linked_changed_or_unreadable_databases_are_not_reused() {
        let mut driver = Driver::new().unwrap();
        let parent = input(&mut driver).unwrap();
        assert!(tree(&parent, false).is_err());
        mkdir(&parent.join("crates"), 0o755).unwrap();
        mkdir(&parent.join("crates/time"), 0o755).unwrap();
        let path = parent.join("crates/time/RUSTSEC-2020-0071.md");
        write_new(
            &path,
            b"Synthetic tree hash fixture, not advisory data",
            0o600,
        )
        .unwrap();
        assert!(tree(&parent, false).is_err());
        let (original, count) = tree(&parent, true).unwrap();
        assert_eq!(count, 1);
        assert_eq!(tree(&parent, false).unwrap().0, original);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"Synthetic changed database").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert_ne!(tree(&parent, false).unwrap().0, original);
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&path, parent.join("link")).unwrap();
        assert!(tree(&parent, false).is_err());
    }

    #[test]
    fn raw_stderr_and_fetch_failures_return_only_generic_errors() {
        let mut driver = Driver::new().unwrap();
        let stdout = driver.logs.join("synthetic-stdout.log");
        write_new(&stdout, evidence(false).to_string().as_bytes(), 0o600).unwrap();
        write_new(
            &driver.logs.join("synthetic-stderr.log"),
            SENSITIVE.as_bytes(),
            0o600,
        )
        .unwrap();
        let db = Database {
            path: driver.logs.clone(),
            commit: REV.into(),
        };
        let error = report(&stdout, &lock(CLEAN.as_bytes()).unwrap(), &db, false).unwrap_err();
        assert!(!error.contains(SENSITIVE));
        // Cancellation models a failed fetch without any provider access.
        driver.cancelled.store(true, Ordering::Relaxed);
        let error = database(&mut driver).err().unwrap();
        assert_eq!(
            error,
            "RustSec retrieval or verification failed; private logs retained"
        );
        assert!(!error.contains(SENSITIVE));
        // Missing or stale receipt must not invoke Git or silently refetch.
        let sequence = driver.sequence;
        assert!(database(&mut driver).is_err());
        assert_eq!(sequence, driver.sequence);
        write_new(
            &driver.logs.join("audit-db/receipt.json"),
            SENSITIVE.as_bytes(),
            0o600,
        )
        .unwrap();
        assert!(database(&mut driver).is_err());
        assert_eq!(sequence, driver.sequence);
        let now = Utc::now();
        let stale = json!({"schema":1,"source":SOURCE,"driver":driver.logs.to_str().unwrap(),
            "commit":REV,"tree_sha256":"a".repeat(64),"advisory_files":1,
            "retrieved":(now - Duration::hours(25)).to_rfc3339()});
        fs::write(driver.logs.join("audit-db/receipt.json"), stale.to_string()).unwrap();
        assert_eq!(
            database(&mut driver).err(),
            Some("stale or future RustSec retrieval receipt")
        );
        assert_eq!(sequence, driver.sequence);
    }

    #[test]
    fn pinned_offline_schema_allows_null_commit_not_missing_or_wrong_metadata() {
        let mut good = evidence(false);
        good["database"]["last-commit"] = Value::Null;
        good["database"]["last-updated"] = Value::Null;
        assert!(parse_value(&good, false).is_ok());
        good["database"]
            .as_object_mut()
            .unwrap()
            .remove("last-commit");
        assert!(parse_value(&good, false).is_err());
        let mut bad = evidence(false);
        bad["settings"]["ignore-extra"] = json!([SENSITIVE]);
        assert!(parse_value(&bad, false).is_err());
        let bytes = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock")).unwrap();
        assert!(lock(&bytes).unwrap().count > 1);
    }

    #[test]
    #[ignore = "authorized local native Docker and public RustSec retrieval only; no registry writes"]
    fn native_packaged_audit_contract() {
        let mut driver = Driver::new().unwrap();
        let image = driver.check("cargo-audit").unwrap();
        contract(&mut driver, &image).unwrap();
        // A second lookup verifies the SAME Driver receipt/tree, without cloning.
        let cached = database(&mut driver).unwrap();
        assert_eq!(cached.path, driver.logs.join("audit-db/database"));
    }
}
