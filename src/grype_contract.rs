//! Native synthetic Grype controls, not image vulnerability/release acceptance.
//! Only DB update has network/write-cache access; raw captures stay private.
use super::{Driver, Result, release};
use chrono::Utc;
use serde_json::{Value, json};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

const ADVISORIES: [&str; 3] = ["RUSTSEC-2020-0071", "GHSA-wcg3-cvx6-7396", "CVE-2020-26235"];
const SEVERITIES: [&str; 6] = ["Unknown", "Negligible", "Low", "Medium", "High", "Critical"];

fn mkdir(path: &Path, mode: u32) -> Result<()> {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "refusing stale Grype control directory")?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| "cannot secure Grype control directory")
}

fn mount(path: &Path, target: &str, readonly: bool) -> Result<String> {
    let source = path
        .to_str()
        .filter(|p| path.is_absolute() && !p.contains([',', '\n', '\r']))
        .ok_or("invalid Grype control mount")?;
    Ok(format!(
        "type=bind,source={source},target={target}{}",
        if readonly { ",readonly" } else { "" }
    ))
}

fn fixture(input: &Path, name: &str, version: &str, filename: &str) -> Result<()> {
    let value = json!({"bomFormat":"CycloneDX", "specVersion":"1.6", "version":1,
        "metadata":{"component":{"type":"application","name":"synthetic-grype-control","version":"0.0.0"}},
        "components":[{"type":"library","bom-ref":format!("pkg:cargo/{name}@{version}"),
            "name":name,"version":version,"purl":format!("pkg:cargo/{name}@{version}")}]});
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(input.join(filename))
        .map_err(|_| "cannot create Grype synthetic input")?;
    file.write_all(value.to_string().as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| file.set_permissions(fs::Permissions::from_mode(0o444)))
        .map_err(|_| "cannot seal Grype synthetic input")
}

#[cfg(test)]
fn no_stderr(stdout: &Path) -> Result<()> {
    if !super::captured_stderr(stdout)?.is_empty() {
        return Err("Grype control emitted diagnostics; private logs retained");
    }
    Ok(())
}

fn report(value: &Value, db: &Value, target: &str, vulnerable: bool) -> Result<usize> {
    if value.pointer("/descriptor/name").and_then(Value::as_str) != Some("grype")
        || value.pointer("/descriptor/version").and_then(Value::as_str) != Some("0.121.0")
        || value
            .pointer("/descriptor/configuration/include-matcher-suppressions")
            .and_then(Value::as_bool)
            != Some(true)
        || value.pointer("/source/type").and_then(Value::as_str) != Some("sbom-file")
        || value.pointer("/source/target").and_then(Value::as_str) != Some(target)
    {
        return Err("Grype control descriptor, input or suppression coverage mismatch");
    }
    let status = value
        .pointer("/descriptor/db/status")
        .ok_or("missing Grype control DB identity")?;
    release::db_status(db, Utc::now())?;
    release::db_status(status, Utc::now())?;
    if status != db {
        return Err("Grype control used a different database");
    }
    release::no_scan_diagnostics(value)?;
    let mut count = 0;
    let mut known = false;
    for key in ["matches", "ignoredMatches"] {
        let findings = match value.get(key) {
            None if key == "ignoredMatches" => continue, // Pinned Go presenter omitempty.
            Some(Value::Array(a)) => a,
            _ => return Err("missing or malformed Grype control findings"),
        };
        for finding in findings {
            let artifact = &finding["artifact"];
            let advisory = &finding["vulnerability"];
            if !SEVERITIES.contains(&advisory["severity"].as_str().unwrap_or(""))
                || advisory["id"].as_str().is_none_or(str::is_empty)
                || artifact["name"] != if vulnerable { "time" } else { "itoa" }
                || artifact["version"] != if vulnerable { "0.1.43" } else { "1.0.18" }
                || artifact["type"] != "rust-crate"
                || artifact["purl"]
                    != if vulnerable {
                        "pkg:cargo/time@0.1.43"
                    } else {
                        "pkg:cargo/itoa@1.0.18"
                    }
            {
                return Err("Grype control finding has unexpected package/advisory identity");
            }
            release::no_scan_diagnostics(finding)?;
            known |= ADVISORIES.contains(&advisory["id"].as_str().unwrap_or(""));
            count += 1; // Ignored, Unknown and Negligible findings are never waived.
        }
    }
    if (!vulnerable && count != 0) || (vulnerable && !known) {
        return Err("Grype clean or known-vulnerable detection control failed");
    }
    Ok(count)
}

fn missing_db(value: &Value) -> Result<()> {
    if value["valid"] != false
        || value["error"] != "database does not exist"
        || value["path"] != "/cache/6/vulnerability.db"
        || value["schemaVersion"] != ""
    {
        return Err("missing Grype DB control lacks the specific status diagnostic");
    }
    Ok(())
}

pub(super) fn check(driver: &mut Driver, image: &str) -> Result<()> {
    if !image.strip_prefix("sha256:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }) {
        return Err("Grype controls require an immutable checked image ID");
    }
    let (arch, _) = driver.native()?;
    if driver.inspect(image, arch)? != image {
        return Err("Grype control image identity mismatch");
    }
    driver.sequence = driver
        .sequence
        .checked_add(1)
        .ok_or("Grype control sequence exhausted")?;
    let root = driver
        .logs
        .join(format!("grype-controls-{}", driver.sequence));
    mkdir(&root, 0o700)?;
    let input = root.join("input");
    let cache = root.join("cache");
    let empty = root.join("missing-cache");
    mkdir(&input, 0o755)?;
    mkdir(&cache, 0o777)?;
    mkdir(&empty, 0o777)?;
    fixture(&input, "itoa", "1.0.18", "clean.cdx.json")?;
    fixture(&input, "time", "0.1.43", "vulnerable.cdx.json")?;
    // Exact exit 1 plus parsed tool diagnostic, never an arbitrary Docker failure.
    let missing = release::scanner(
        driver,
        image,
        &["db", "status", "--output", "json"],
        &[mount(&empty, "/cache", true)?],
        false,
        1,
    )?;
    missing_db(&release::read_json(&missing)?)?;
    release::scanner(
        driver,
        image,
        &["db", "update"],
        &[mount(&cache, "/cache", false)?],
        true,
        0,
    )?;
    let mounts = [
        mount(&cache, "/cache", true)?,
        mount(&input, "/input", true)?,
    ];
    let status = release::scanner(
        driver,
        image,
        &["db", "status", "--output", "json"],
        &mounts,
        false,
        0,
    )?;
    let db = release::read_json(&status)?;
    release::db_status(&db, Utc::now())?;
    for (filename, vulnerable) in [("clean.cdx.json", false), ("vulnerable.cdx.json", true)] {
        let target = format!("/input/{filename}");
        let source = format!("sbom:{target}");
        let output = release::scanner(
            driver,
            image,
            &[&source, "--output", "json"],
            &mounts,
            false,
            0,
        )?;
        report(&release::read_json(&output)?, &db, &target, vulnerable)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Value {
        json!({"valid":true,"schemaVersion":"v6.1.10","built":Utc::now().to_rfc3339()})
    }
    fn clean(db: &Value) -> Value {
        json!({"descriptor":{"name":"grype","version":"0.121.0","db":{"status":db},
            "configuration":{"include-matcher-suppressions":true}},"source":{"type":"sbom-file","target":"/input/clean.cdx.json"},"matches":[]})
    }
    fn finding(severity: &str) -> Value {
        json!({"artifact":{"name":"time","version":"0.1.43","type":"rust-crate","purl":"pkg:cargo/time@0.1.43"},
            "vulnerability":{"id":ADVISORIES[0],"severity":severity}})
    }

    #[test]
    fn clean_rejects_all_severities_including_ignored_and_malformed_findings() {
        let db = db();
        let good = clean(&db);
        assert_eq!(report(&good, &db, "/input/clean.cdx.json", false), Ok(0));
        for key in ["matches", "ignoredMatches"] {
            for severity in SEVERITIES {
                let mut bad = good.clone();
                let mut f = finding(severity);
                f["artifact"] = json!({"name":"itoa","version":"1.0.18","type":"rust-crate","purl":"pkg:cargo/itoa@1.0.18"});
                bad[key] = json!([f]);
                assert!(report(&bad, &db, "/input/clean.cdx.json", false).is_err());
            }
            for invalid in [Value::Null, json!({}), json!("[]")] {
                let mut bad = good.clone();
                bad[key] = invalid;
                assert!(report(&bad, &db, "/input/clean.cdx.json", false).is_err());
            }
        }
    }

    #[test]
    fn rejects_descriptor_db_coverage_diagnostics_and_missing_matches() {
        let db = db();
        let good = clean(&db);
        for (pointer, invalid) in [
            ("/descriptor/name", json!("syft")),
            ("/descriptor/version", json!("0.120.0")),
            (
                "/descriptor/configuration/include-matcher-suppressions",
                json!(false),
            ),
            ("/descriptor/db/status/valid", json!(false)),
            ("/descriptor/db/status/built", json!("2000-01-01T00:00:00Z")),
            ("/source/type", json!("image")),
            ("/source/target", json!("other")),
            ("/matches", Value::Null),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = invalid;
            assert!(report(&bad, &db, "/input/clean.cdx.json", false).is_err());
        }
        for key in ["error", "errors", "alerts", "alertsByPackage", "warnings"] {
            for invalid in [
                json!(["synthetic"]),
                json!({"synthetic":true}),
                json!(false),
                Value::Null,
            ] {
                let mut bad = good.clone();
                bad[key] = invalid;
                assert!(report(&bad, &db, "/input/clean.cdx.json", false).is_err());
            }
        }
        let mut bad = good;
        bad.as_object_mut().unwrap().remove("matches");
        assert!(report(&bad, &db, "/input/clean.cdx.json", false).is_err());
    }

    #[test]
    fn vulnerable_requires_known_advisory_on_exact_package_even_when_ignored() {
        let db = db();
        let target = "/input/clean.cdx.json";
        assert!(report(&clean(&db), &db, target, true).is_err());
        for key in ["matches", "ignoredMatches"] {
            let mut good = clean(&db);
            good[key] = json!([finding("High")]);
            assert_eq!(report(&good, &db, target, true), Ok(1));
            for (pointer, invalid) in [
                ("/artifact/name", json!("other")),
                ("/artifact/version", json!("0.1.44")),
                ("/artifact/purl", json!("pkg:npm/time@0.1.43")),
                ("/artifact/type", json!("npm")),
                ("/vulnerability/id", json!("unrelated")),
                ("/vulnerability/severity", json!("new")),
            ] {
                let mut bad = good.clone();
                *bad[key][0].pointer_mut(pointer).unwrap() = invalid;
                assert!(report(&bad, &db, target, true).is_err());
            }
        }
    }

    #[test]
    fn missing_db_requires_specific_tool_status_not_generic_failure() {
        let good = json!({"valid":false,"error":"database does not exist","path":"/cache/6/vulnerability.db","schemaVersion":""});
        assert!(missing_db(&good).is_ok());
        for (key, invalid) in [
            ("valid", json!(true)),
            ("error", json!("permission denied")),
            ("path", json!("/other")),
            ("schemaVersion", json!("v6.1.10")),
        ] {
            let mut bad = good.clone();
            bad[key] = invalid;
            assert!(missing_db(&bad).is_err());
        }
        for bad in [
            json!({}),
            json!({"valid":true,"error":"database does not exist"}),
            json!({"valid":false,"error":"permission denied"}),
            json!({"valid":false,"error":"Docker failed"}),
        ] {
            assert!(missing_db(&bad).is_err());
        }
    }

    #[test]
    fn rejects_changed_database_identity_and_future_or_incomplete_status() {
        let db = db();
        for (key, invalid) in [
            (
                "built",
                json!((Utc::now() + chrono::Duration::minutes(10)).to_rfc3339()),
            ),
            ("schemaVersion", json!("v6.1.9")),
            ("from", json!("synthetic-other-db")),
            ("path", json!("/other/database.db")),
            ("error", json!("synthetic error")),
        ] {
            let mut bad = clean(&db);
            bad["descriptor"]["db"]["status"][key] = invalid;
            assert!(report(&bad, &db, "/input/clean.cdx.json", false).is_err());
        }
        let mut bad = clean(&db);
        bad["descriptor"]["configuration"]
            .as_object_mut()
            .unwrap()
            .clear();
        assert!(report(&bad, &db, "/input/clean.cdx.json", false).is_err());
        bad["descriptor"]["db"]["status"] = json!({});
        assert!(report(&bad, &db, "/input/clean.cdx.json", false).is_err());
    }

    #[test]
    fn mutable_or_malformed_candidates_fail_before_docker() {
        let mut driver = Driver::new().unwrap();
        for image in [
            "grype:latest".to_owned(),
            "sha256:short".into(),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "g".repeat(64)),
        ] {
            assert!(check(&mut driver, &image).is_err());
        }
        assert_eq!(driver.sequence, 0);
    }

    #[test]
    fn private_capture_and_fixture_permissions_fail_closed() {
        let driver = Driver::new().unwrap();
        let root = driver.logs.join("permissions");
        mkdir(&root, 0o700).unwrap();
        assert!(mkdir(&root, 0o700).is_err());
        let input = root.join("input");
        mkdir(&input, 0o755).unwrap();
        let cache = root.join("cache");
        mkdir(&cache, 0o777).unwrap();
        assert_eq!(
            fs::metadata(cache).unwrap().permissions().mode() & 0o777,
            0o777
        );
        fixture(&input, "itoa", "1.0.18", "clean.json").unwrap();
        assert!(fixture(&input, "itoa", "1.0.18", "clean.json").is_err());
        for (path, mode) in [
            (&root, 0o700),
            (&input, 0o755),
            (&input.join("clean.json"), 0o444),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
        let out = root.join("1-stdout.log");
        let err = root.join("1-stderr.log");
        assert!(no_stderr(&out).is_err());
        fs::write(&err, b"").unwrap();
        assert!(no_stderr(&out).is_ok());
        fs::write(&err, b"synthetic-private-error").unwrap();
        assert!(no_stderr(&out).is_err());
        fs::remove_file(&err).unwrap();
        std::os::unix::fs::symlink(input.join("clean.json"), &err).unwrap();
        assert!(no_stderr(&out).is_err());
    }

    #[test]
    #[ignore = "authorized local native Docker; public Grype DB and synthetic inputs only"]
    fn native_synthetic_controls() {
        let mut driver = Driver::new().unwrap();
        let image = driver
            .check("grype")
            .expect("native Grype build/smoke failed; private logs retained");
        check(&mut driver, &image).expect("Grype synthetic controls failed; private logs retained");
        let mut counts = Vec::new();
        for entry in fs::read_dir(&driver.logs).unwrap() {
            let path = entry.unwrap().path();
            if path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with("-stdout.log")
                && let Ok(value) = release::read_json(&path)
                && let Some(matches) = value["matches"].as_array()
            {
                counts.push(matches.len() + value["ignoredMatches"].as_array().map_or(0, Vec::len));
            }
        }
        counts.sort();
        assert_eq!(counts.len(), 2);
        assert_eq!(counts[0], 0);
        assert!(counts[1] > 0);
        println!(
            "Grype native controls: findings={counts:?}, missing DB exit=1; image {image}; not release acceptance"
        );
        println!("Private evidence: {}", driver.logs.display());
    }
}
