//! Explicit Debian Gitleaks runtime experiment. Never authorizes production publication.
#[path = "debian_candidate.rs"]
mod candidate;
use crate::{Driver, Result, release};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::Command,
};
fn hash(path: &Path, limit: u64) -> Result<String> {
    let mut input = release::regular(path, limit)?;
    let mut digest = Sha256::new();
    let mut count = 0;
    let mut buffer = [0; 32768];
    loop {
        let n = input
            .read(&mut buffer)
            .map_err(|_| "cannot read experiment input")?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > limit {
            return Err("experiment input overflow");
        }
        digest.update(&buffer[..n]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "cannot create experiment output")?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "cannot write experiment output")
}
fn members(data: &[u8]) -> Result<BTreeMap<&str, &[u8]>> {
    if !data.starts_with(b"!<arch>\n") {
        return Err("not a Debian ar archive");
    }
    let mut offset = 8;
    let mut result = BTreeMap::new();
    while offset < data.len() {
        let header = data.get(offset..offset + 60).ok_or("truncated ar header")?;
        if &header[58..] != b"`\n" {
            return Err("invalid ar header");
        }
        let name = std::str::from_utf8(&header[..16])
            .map_err(|_| "ar name encoding")?
            .trim_end()
            .trim_end_matches('/');
        if !matches!(name, "debian-binary" | "control.tar.xz" | "data.tar.xz") {
            return Err("unreviewed Debian archive member");
        }
        let size = std::str::from_utf8(&header[48..58])
            .map_err(|_| "ar size encoding")?
            .trim()
            .parse::<usize>()
            .map_err(|_| "ar size")?;
        if size > 32 * 1024 * 1024 {
            return Err("ar size limit");
        }
        offset += 60;
        let end = offset.checked_add(size).ok_or("ar offset overflow")?;
        let body = data.get(offset..end).ok_or("truncated ar member")?;
        if result.insert(name, body).is_some() {
            return Err("duplicate ar member");
        }
        offset = end;
        if !size.is_multiple_of(2) {
            if data.get(offset) != Some(&b'\n') {
                return Err("ar padding");
            }
            offset += 1;
        }
    }
    if result.len() != 3 || result.get("debian-binary") != Some(&&b"2.0\n"[..]) {
        return Err("incomplete Debian archive");
    }
    Ok(result)
}
fn fields(block: &str) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::<String, String>::new();
    let mut key = String::new();
    for line in block.lines() {
        if line.starts_with([' ', '\t']) {
            result
                .get_mut(&key)
                .ok_or("orphan Debian continuation")?
                .push_str(&format!("\n{line}"));
        } else {
            let (name, value) = line
                .split_once(": ")
                .or_else(|| line.strip_suffix(':').map(|s| (s, "")))
                .ok_or("malformed Debian field")?;
            if result.insert(name.to_owned(), value.to_owned()).is_some() {
                return Err("duplicate Debian field");
            }
            key = name.to_owned();
        }
    }
    Ok(result)
}
fn select(path: &Path, names: &[&str]) -> Result<BTreeMap<String, Vec<Value>>> {
    let input = release::regular(path, 128 * 1024 * 1024)?;
    let mut blocks = BufReader::new(input).split(b'\n');
    let mut block = String::new();
    let mut records = BTreeMap::<String, Vec<Value>>::new();
    let mut total = 0;
    for line in &mut blocks {
        let line = line.map_err(|_| "cannot read package index")?;
        total += line.len() + 1;
        if total > 128 * 1024 * 1024 || block.len() + line.len() > 1024 * 1024 {
            return Err("package index budget exceeded");
        }
        let text = std::str::from_utf8(&line).map_err(|_| "package index encoding")?;
        if text.is_empty() {
            if !block.is_empty() {
                let record = fields(&block)?;
                if let Some(name) = record.get("Package")
                    && names.contains(&name.as_str())
                {
                    records.entry(name.clone()).or_default().push(json!(record));
                }
                block.clear();
            }
        } else {
            block.push_str(text);
            block.push('\n');
        }
    }
    if !block.is_empty() {
        return Err("unterminated package stanza");
    }
    Ok(records)
}
fn check_index(release: &str, name: &str, input: &Path) -> Result<()> {
    let section = release
        .split_once("\nSHA256:\n")
        .ok_or("missing SHA256 index")?
        .1;
    let lines: Vec<_> = section
        .lines()
        .take_while(|line| line.starts_with(' '))
        .filter_map(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            (parts.len() == 3 && parts[2] == name).then_some(parts)
        })
        .collect();
    if lines.len() != 1 {
        return Err("missing or ambiguous signed index");
    }
    let size = lines[0][1].parse::<u64>().map_err(|_| "bad signed size")?;
    if fs::metadata(input).map_err(|_| "missing index")?.len() != size
        || hash(input, 64 * 1024 * 1024)? != lines[0][0]
    {
        return Err("signed index size/hash mismatch");
    }
    Ok(())
}
#[test]
fn debian_stanzas_reject_duplicate_or_orphan_fields() {
    assert!(fields("Package: git\nVersion: 1\nVersion: 2\n").is_err());
    assert!(fields(" orphan\nPackage: git\n").is_err());
    let good = fields("Package: git\nChecksums-Sha256:\n hash size file\n").unwrap();
    assert_eq!(good["Checksums-Sha256"], "\n hash size file");
}
#[test]
#[ignore = "approved public Debian metadata captures; verifies signatures with isolated keyrings, no image/host changes"]
fn authenticate_debian_runtime_metadata() {
    let mut driver = Driver::new().unwrap();
    let input = driver.root.join(".work/approval-suppliers/http");
    let keyring = driver.logs.join("debian.gpg");
    for (name, expected) in [
        ("debian13-key", "04B54C3CDCA79751B16BC6B5225629DF75B188BD"),
        ("debian12-key", "B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8"),
        (
            "debian12-security-key",
            "05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0",
        ),
        (
            "debian12-release-key",
            "4D64FEC119C2029067D6E791F8D2585B8783D481",
        ),
        (
            "debian13-security-key",
            "5E04A1E3223A19A20706E20F9904613D4CCE68C6",
        ),
        (
            "debian13-release-key",
            "41587F7DB8C774BCCF131416762F67A0B2C39DE4",
        ),
    ] {
        let key = input.join(format!("{name}.body"));
        let mut show = Command::new("gpg");
        show.args(["--batch", "--no-options", "--homedir"])
            .arg(&driver.logs)
            .args(["--no-autostart", "--with-colons", "--show-keys"])
            .arg(&key);
        let output = driver.execute(show, 30, false, 0).unwrap();
        let text = fs::read_to_string(output).unwrap();
        let fingerprint = text
            .lines()
            .find(|line| line.starts_with("fpr:"))
            .unwrap()
            .split(':')
            .nth(9)
            .unwrap();
        assert_eq!(
            text.lines().filter(|line| line.starts_with("pub:")).count(),
            1
        );
        assert_eq!(fingerprint, expected);
        let mut import = Command::new("gpg");
        import
            .args(["--batch", "--no-options", "--homedir"])
            .arg(&driver.logs)
            .args(["--no-autostart", "--no-default-keyring", "--keyring"])
            .arg(&keyring)
            .arg("--import")
            .arg(key);
        driver.execute(import, 30, false, 0).unwrap();
    }
    let mut result = json!({"scope":"authenticated candidate metadata, not release approval","packages":{},"sources":{}});
    for security in [false, true] {
        let prefix = if security {
            "debian13-security"
        } else {
            "debian13"
        };
        let signed = input.join(format!("{prefix}-inrelease.body"));
        let mut verify = Command::new("gpgv");
        verify
            .arg("--homedir")
            .arg(&driver.logs)
            .arg("--keyring")
            .arg(&keyring)
            .arg("--status-fd=1")
            .arg(&signed);
        let output = driver.execute(verify, 30, false, 0).unwrap();
        let status = fs::read_to_string(output).unwrap();
        assert!(status.contains("[GNUPG:] VALIDSIG "));
        for forbidden in [
            "BADSIG",
            "ERRSIG",
            "EXPSIG",
            "EXPKEYSIG",
            "REVKEYSIG",
            "NO_PUBKEY",
        ] {
            assert!(!status.contains(forbidden));
        }
        let release = String::from_utf8(release::bytes(&signed, 1024 * 1024).unwrap()).unwrap();
        let altered = driver.logs.join(format!("{prefix}-bad.inrelease"));
        assert!(release.contains("Origin: Debian"));
        write(
            &altered,
            release
                .replacen("Origin: Debian", "Origin: Debiam", 1)
                .as_bytes(),
        )
        .unwrap();
        let mut negative = Command::new("gpgv");
        negative
            .arg("--homedir")
            .arg(&driver.logs)
            .arg("--keyring")
            .arg(&keyring)
            .arg(altered);
        driver.execute(negative, 30, false, 1).unwrap();
        for (kind, arch) in [
            ("packages", "amd64"),
            ("packages", "arm64"),
            ("sources", ""),
        ] {
            let suffix = if arch.is_empty() {
                String::new()
            } else {
                format!("-{arch}")
            };
            let stem = format!("{prefix}-{kind}{suffix}");
            let filename = format!("{stem}{}.body", if security { "-xz" } else { "" });
            let compressed = input.join(filename);
            let index = if kind == "sources" {
                format!("main/source/Sources.{}", if security { "xz" } else { "gz" })
            } else {
                format!(
                    "main/binary-{arch}/Packages.{}",
                    if security { "xz" } else { "gz" }
                )
            };
            check_index(&release, &index, &compressed).unwrap();
            let target = driver.logs.join(format!("{stem}.txt"));
            let mut unpack = Command::new(if security { "xz" } else { "gzip" });
            unpack.args(["--decompress", "--stdout"]);
            if security {
                unpack.arg("--memlimit-decompress=64MiB");
            }
            unpack.arg(compressed);
            driver
                .execute_to(unpack, 60, false, 0, Some((&target, 128 * 1024 * 1024)))
                .unwrap();
            let names = if kind == "sources" {
                vec!["git", "glibc", "pcre2", "zlib"]
            } else {
                vec!["git", "libc6", "libpcre2-8-0", "zlib1g"]
            };
            result[kind][format!("{prefix}{suffix}")] = json!(select(&target, &names).unwrap());
        }
    }
    write(
        &driver.logs.join("debian-metadata.json"),
        &serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
}

#[test]
fn debian_signed_index_rejects_changed_bytes_sizes_and_ambiguity() {
    let driver = Driver::new().unwrap();
    let input = driver.logs.join("index");
    write(&input, b"abc").unwrap();
    let digest = hash(&input, 3).unwrap();
    let line = format!(" {digest} 3 main/index\n");
    let release = format!("SHA256:\n{line}");
    assert!(check_index(&format!("\n{release}"), "main/index", &input).is_ok());
    for bad in [
        format!("\n{release}{line}"),
        format!("\n{release}").replace(" 3 ", " 4 "),
        format!("\n{release}").replace(&digest, &"0".repeat(64)),
    ] {
        assert!(check_index(&bad, "main/index", &input).is_err());
    }
    assert!(check_index(&format!("\n{release}"), "missing", &input).is_err());
    for invalid in [b"not ar".as_slice(), b"!<arch>\n", b"!<arch>\ntruncated"] {
        assert!(members(invalid).is_err());
    }
}

#[test]
#[ignore = "fixed authenticated public Debian package/source captures; no package scripts, image or host changes"]
fn inspect_debian_runtime_payloads() {
    let mut driver = Driver::new().unwrap();
    let input = driver.root.join(".work/approval-suppliers/http");
    let plan_path = driver
        .root
        .join(".work/approval-suppliers/debian-runtime-plan.json");
    assert_eq!(
        hash(&plan_path, 1024 * 1024).unwrap(),
        "41d3a8f66c895b82078d034f94b1a7a2c728959a48022861c3045c9315e7a29d"
    );
    let plan: Value =
        serde_json::from_slice(&release::bytes(&plan_path, 1024 * 1024).unwrap()).unwrap();
    assert_eq!(
        hash(
            &driver.root.join(plan["metadata_capture"].as_str().unwrap()),
            1024 * 1024
        )
        .unwrap(),
        "52d7d4a7c82886ed7920f585848aac3201632243571abf44bdc36c237a429ff7"
    );
    let assets = plan["assets"].as_array().unwrap();
    assert_eq!(assets.len(), 20);
    for asset in assets {
        let file = input.join(format!("{}.body", asset["id"].as_str().unwrap()));
        assert_eq!(
            fs::metadata(&file).unwrap().len(),
            asset["size"].as_u64().unwrap()
        );
        assert_eq!(
            hash(&file, 32 * 1024 * 1024).unwrap(),
            asset["sha256"].as_str().unwrap()
        );
    }
    for source in plan["sources"].as_array().unwrap() {
        let ids = source["assets"].as_array().unwrap();
        assert_eq!(ids.len(), 3);
        let dsc = String::from_utf8(
            release::bytes(
                &input.join(format!("{}.body", ids[0].as_str().unwrap())),
                1024 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        let body = dsc
            .strip_prefix("-----BEGIN PGP SIGNED MESSAGE-----\n")
            .unwrap()
            .split_once("\n\n")
            .unwrap()
            .1
            .split_once("\n-----BEGIN PGP SIGNATURE-----")
            .unwrap()
            .0;
        let descriptor = fields(body).unwrap();
        assert_eq!(descriptor["Source"], source["package"].as_str().unwrap());
        assert_eq!(descriptor["Version"], source["version"].as_str().unwrap());
        let checks: Vec<_> = descriptor["Checksums-Sha256"].trim().lines().collect();
        assert_eq!(checks.len(), 2);
        for id in &ids[1..] {
            let asset = assets.iter().find(|a| a["id"] == *id).unwrap();
            let filename = asset["url"].as_str().unwrap().rsplit('/').next().unwrap();
            let expected = format!(
                "{} {} {filename}",
                asset["sha256"].as_str().unwrap(),
                asset["size"].as_u64().unwrap()
            );
            assert_eq!(
                checks.iter().filter(|line| line.trim() == expected).count(),
                1
            );
        }
    }
    let mut result = json!({"approval":false,"source_archives_verified":12,"binary_packages_verified":8,"files":[]});
    for package in plan["packages"].as_array().unwrap() {
        let id = package["asset"].as_str().unwrap();
        let name = package["package"].as_str().unwrap();
        let arch = package["architecture"].as_str().unwrap();
        let data = release::bytes(&input.join(format!("{id}.body")), 32 * 1024 * 1024).unwrap();
        let members = members(&data).unwrap();
        let mut found = 0;
        for part in ["control", "data"] {
            let compressed = driver.logs.join(format!("{id}-{part}.xz"));
            write(&compressed, members[format!("{part}.tar.xz").as_str()]).unwrap();
            let target = driver.logs.join(format!("{id}-{part}.tar"));
            let mut unpack = Command::new("xz");
            unpack
                .args(["--decompress", "--stdout", "--memlimit-decompress=64MiB"])
                .arg(compressed);
            driver
                .execute_to(unpack, 60, false, 0, Some((&target, 128 * 1024 * 1024)))
                .unwrap();
            let mut archive =
                tar::Archive::new(release::regular(&target, 128 * 1024 * 1024).unwrap());
            for entry in archive.entries().unwrap() {
                let mut entry = entry.unwrap();
                let path = entry
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .trim_start_matches("./")
                    .to_owned();
                if !entry.header().entry_type().is_file() {
                    continue;
                }
                let basename = Path::new(&path).file_name().unwrap().to_str().unwrap();
                if part == "control" && path == "control" {
                    let mut content = String::new();
                    entry
                        .take(1024 * 1024)
                        .read_to_string(&mut content)
                        .unwrap();
                    let values = fields(content.trim_end()).unwrap();
                    assert_eq!(values["Package"], name);
                    assert_eq!(values["Architecture"], arch);
                    assert_eq!(values["Version"], package["version"].as_str().unwrap());
                    write(
                        &driver.logs.join(format!("{id}-control.txt")),
                        content.as_bytes(),
                    )
                    .unwrap();
                    continue;
                }
                let wanted = path == "usr/bin/git"
                    || basename == "copyright"
                    || (name == "libc6"
                        && matches!(
                            basename,
                            "libc.so.6" | "ld-linux-x86-64.so.2" | "ld-linux-aarch64.so.1"
                        ))
                    || (name == "libpcre2-8-0" && basename.starts_with("libpcre2-8.so.0."))
                    || (name == "zlib1g" && basename == "libz.so.1.3.1");
                if !wanted {
                    continue;
                }
                let limit = 16 * 1024 * 1024;
                assert!(entry.size() <= limit);
                let mut content = Vec::new();
                entry.read_to_end(&mut content).unwrap();
                assert!(content.len() <= limit as usize);
                let destination = driver.logs.join(format!("{id}-{basename}"));
                write(&destination, &content).unwrap();
                found += 1;
                result["files"].as_array_mut().unwrap().push(json!({"package":name,"architecture":arch,"path":path,"size":content.len(),"sha256":hash(&destination,limit).unwrap(),"capture":destination.strip_prefix(&driver.root).unwrap()}));
                if content.starts_with(b"\x7fELF") {
                    let mut inspect = Command::new("llvm-readelf");
                    inspect
                        .args(["--file-header", "--program-headers", "--dynamic"])
                        .arg(destination);
                    let output = driver.execute(inspect, 30, false, 0).unwrap();
                    let raw =
                        String::from_utf8(release::bytes(&output, 1024 * 1024).unwrap()).unwrap();
                    result["files"].as_array_mut().unwrap().last_mut().unwrap()["elf_summary"] = json!(
                        raw.lines()
                            .filter(|line| line.contains("Machine:")
                                || line.contains("interpreter:")
                                || line.contains("(NEEDED)")
                                || line.contains("(SONAME)"))
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
        assert_eq!(found, if name == "libc6" { 3 } else { 2 });
    }
    write(
        &driver.logs.join("debian-payloads.json"),
        &serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
}

#[test]
fn debian_ar_rejects_duplicates_unknown_members_padding_and_oversize() {
    fn member(name: &str, data: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            0,
            0,
            0,
            "100644",
            data.len()
        )
        .into_bytes();
        out.extend(data);
        if !data.len().is_multiple_of(2) {
            out.push(b'\n');
        }
        out
    }
    let mut good = b"!<arch>\n".to_vec();
    for (name, data) in [
        ("debian-binary", b"2.0\n".as_slice()),
        ("control.tar.xz", b"x"),
        ("data.tar.xz", b"y"),
    ] {
        good.extend(member(name, data));
    }
    assert_eq!(members(&good).unwrap().len(), 3);
    let mut duplicate = good.clone();
    duplicate.extend(member("data.tar.xz", b"z"));
    assert_eq!(members(&duplicate).unwrap_err(), "duplicate ar member");
    let mut unknown = good.clone();
    unknown.extend(member("../unreviewed", b"z"));
    assert_eq!(
        members(&unknown).unwrap_err(),
        "unreviewed Debian archive member"
    );
    let mut padding = good.clone();
    *padding.last_mut().unwrap() = 0;
    assert_eq!(members(&padding).unwrap_err(), "ar padding");
    let mut oversized = b"!<arch>\n".to_vec();
    oversized.extend(
        format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            "data.tar.xz",
            0,
            0,
            0,
            "100644",
            32 * 1024 * 1024 + 1
        )
        .as_bytes(),
    );
    assert_eq!(members(&oversized).unwrap_err(), "ar size limit");
    assert!(members(&good[..good.len() - 3]).is_err());
}

#[test]
fn debian_evidence_keeps_findings_and_incomplete_approvals_explicit() {
    let value: Value =
        serde_json::from_slice(include_bytes!("../licenses/gitleaks-debian-evidence.json"))
            .unwrap();
    for key in [
        "approval",
        "complete_corresponding_source",
        "complete_notice_coverage",
        "independent_reproducible_build",
        "recipient_source_delivery_complete",
        "artifact_provenance_reviewed",
    ] {
        assert_eq!(value[key], false);
    }
    assert_eq!(value["assets"].as_array().unwrap().len(), 20);
    assert_eq!(value["packages"].as_array().unwrap().len(), 8);
    assert_eq!(value["sources"].as_array().unwrap().len(), 4);
    assert_eq!(value["selected_files"].as_array().unwrap().len(), 18);
    for arch in ["amd64", "arm64"] {
        assert_eq!(
            value["packages"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|p| p["architecture"] == arch)
                .count(),
            4
        );
        assert_eq!(
            value["selected_files"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|p| p["architecture"] == arch)
                .count(),
            9
        );
    }
    let native = &value["native_arm64"];
    assert_eq!(native["status"], "blocked");
    assert_eq!(native["approval"], false);
    assert_eq!(native["release_accepted"], false);
    assert_eq!(native["amd64_execution"], "not-run");
    assert_eq!(native["runtime_completion_issue"], "not-resolved");
    assert_eq!(native["risk"]["blocking"], 26);
    assert_eq!(native["risk"]["accepted"], 1);
    assert_eq!(
        native["counts"],
        json!({"Critical":0,"High":3,"Medium":10,"Low":3,"Negligible":10,"Unknown":1,"ignoredMatches":0})
    );
    let findings = native["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 27);
    for (name, count) in [
        ("libc6", 21),
        ("git", 3),
        ("zlib1g", 2),
        ("golang.org/x/crypto", 1),
    ] {
        assert_eq!(
            findings.iter().filter(|f| f["package"] == name).count(),
            count
        );
    }
    for finding in findings {
        assert_eq!(finding["suppressed"], false);
        assert_eq!(finding["fix"]["versions"], json!([]));
    }
    assert_eq!(
        findings
            .iter()
            .filter(|f| f["id"] == "GO-2026-5932"
                && f["package"] == "golang.org/x/crypto"
                && f["version"] == "v0.58.0")
            .count(),
        1
    );
}

#[test]
#[ignore = "read-only integrity replay of retained Debian captures; does not rerun native commands or authorize publication"]
fn recorded_debian_sources_and_native_observation_keep_their_hashes() {
    let driver = Driver::new().unwrap();
    let evidence: Value =
        serde_json::from_slice(include_bytes!("../licenses/gitleaks-debian-evidence.json"))
            .unwrap();
    for asset in evidence["assets"].as_array().unwrap() {
        let file = driver.root.join(format!(
            ".work/approval-suppliers/http/{}.body",
            asset["id"].as_str().unwrap()
        ));
        assert_eq!(
            fs::metadata(&file).unwrap().len(),
            asset["size"].as_u64().unwrap()
        );
        assert_eq!(
            hash(&file, 32 * 1024 * 1024).unwrap(),
            asset["sha256"].as_str().unwrap()
        );
    }
    for input in evidence["authenticated_metadata_inputs"]
        .as_array()
        .unwrap()
        .iter()
        .chain(evidence["selected_files"].as_array().unwrap())
    {
        let file = driver.root.join(input["capture"].as_str().unwrap());
        assert_eq!(
            fs::metadata(&file).unwrap().len(),
            input["size"].as_u64().unwrap()
        );
        assert_eq!(
            hash(&file, 64 * 1024 * 1024).unwrap(),
            input["sha256"].as_str().unwrap()
        );
    }
    let native = &evidence["native_arm64"];
    let folder = driver.root.join(".work/check-20345-1793280761614233000");
    for (file, key, limit) in [
        ("debian-image.tar", "archive_sha256", release::TAR_LIMIT),
        ("syft.json", "sbom_sha256", release::JSON_LIMIT),
        ("50-stdout.log", "report_sha256", release::JSON_LIMIT),
    ] {
        assert_eq!(
            hash(&folder.join(file), limit).unwrap(),
            native[key].as_str().unwrap()
        );
    }
    assert_eq!(
        crate::archive::config_digest(&folder.join("debian-image.tar"), "arm64", "local").unwrap(),
        native["config"]
    );
    let sbom = release::read_json(&folder.join("syft.json")).unwrap();
    let original: Value =
        serde_json::from_slice(include_bytes!("../inventory/gitleaks-production.json")).unwrap();
    let expected: std::collections::BTreeSet<_> = original["locations"]["/usr/local/bin/gitleaks"]
        .as_array()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect();
    let observed: std::collections::BTreeSet<_> = sbom["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["type"] == "go-module")
        .map(|p| {
            assert_eq!(p["metadata"]["goCompiledVersion"], "go1.27.3");
            json!([p["type"], p["name"], p["version"], p["foundBy"]]).to_string()
        })
        .collect();
    assert_eq!(observed.len(), 64);
    assert_eq!(observed, expected);
}
