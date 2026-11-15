//! Fixed read-only current native/source observation; never a release approval.
use crate::{
    Result,
    release::{hash, read_json, write_json},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Read},
    path::{Component, Path},
};

struct Files {
    hashes: BTreeMap<String, String>,
    texts: BTreeMap<String, Vec<u8>>,
}
fn inspect(reader: impl Read) -> Result<Files> {
    let mut archive = tar::Archive::new(reader.take(1024 * 1024 * 1024 + 1));
    archive.set_ignore_zeros(true);
    let mut hashes = BTreeMap::new();
    let mut texts = BTreeMap::new();
    let mut total = 0u64;
    for item in archive.entries().map_err(|_| "invalid source archive")? {
        let mut item = item.map_err(|_| "invalid source entry")?;
        let path = item.path().map_err(|_| "invalid source path")?.into_owned();
        if path
            .components()
            .any(|p| !matches!(p, Component::Normal(_) | Component::CurDir))
        {
            return Err("escaping source path");
        }
        if !item.header().entry_type().is_file() {
            continue;
        }
        let name = path
            .to_str()
            .ok_or("invalid source filename")?
            .trim_start_matches("./")
            .to_owned();
        let size = item.size();
        total = total.checked_add(size).ok_or("source size overflow")?;
        // Non-control source blobs are hashed in fixed 64 KiB chunks under
        // the unchanged 1 GiB aggregate bound; never buffer a complete blob.
        if total > 1024 * 1024 * 1024 || hashes.len() >= 100_000 {
            return Err("source capture budget exceeded");
        }
        let keep = matches!(name.as_str(), ".PKGINFO" | ".source.sha256")
            || name.ends_with("/SOURCES.sha256");
        if keep && size > 1024 * 1024 {
            return Err("source control byte limit");
        }
        let mut digest = Sha256::new();
        let mut data = Vec::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = item
                .read(&mut buffer)
                .map_err(|_| "cannot read source entry")?;
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
            if keep {
                data.extend_from_slice(&buffer[..n]);
            }
        }
        let digest = digest
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if hashes.insert(name.clone(), digest).is_some() {
            return Err("duplicate source entry");
        }
        if keep {
            texts.insert(name, data);
        }
    }
    Ok(Files { hashes, texts })
}
// GCC's 168 MiB companion exceeds the fixed single-transfer budget. Fetch
// three <=64 MiB ranges, retaining the 1 GiB total source-inspection budget.
fn collect_gcc_ranges(driver: &mut crate::Driver, file: &Path, supplier_arch: &str) -> Result<()> {
    use std::io::Write;
    let total = match supplier_arch {
        "x86_64" => 168_507_271u64,
        "aarch64" => 168_507_355u64,
        _ => return Err("unreviewed GCC source architecture"),
    };
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(file)
        .map_err(|_| "cannot create partitioned source capture")?;
    let mut start = 0;
    while start < total {
        let end = (start + 64 * 1024 * 1024 - 1).min(total - 1);
        let part = file.with_extension(format!("part-{start}"));
        let headers = file.with_extension(format!("headers-{start}"));
        let mut command = std::process::Command::new("/usr/bin/curl");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                "--disable",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-time",
                "180",
                "--max-filesize",
                "67108864",
                "--range",
            ])
            .arg(format!("{start}-{end}"))
            .arg("--dump-header")
            .arg(&headers)
            .arg("--output")
            .arg(&part)
            .arg(format!(
                "https://apk.cgr.dev/chainguard/{supplier_arch}/gcc-source-16.2.0-r4.apk"
            ));
        driver.execute(command, 190, false, 0)?;
        let response = crate::release::bytes(&headers, 16 * 1024)?;
        let response = std::str::from_utf8(&response)
            .map_err(|_| "invalid range response")?
            .to_ascii_lowercase();
        if !response
            .lines()
            .any(|line| line.trim() == format!("content-range: bytes {start}-{end}/{total}"))
            || std::fs::metadata(&part)
                .map_err(|_| "missing source partition")?
                .len()
                != end - start + 1
        {
            return Err("source partition identity/size mismatch");
        }
        let copied = std::io::copy(
            &mut File::open(&part)
                .map_err(|_| "cannot open source partition")?
                .take(64 * 1024 * 1024 + 1),
            &mut output,
        )
        .map_err(|_| "cannot stream source partition")?;
        if copied != end - start + 1 {
            return Err("incomplete source partition");
        }
        start = end + 1;
    }
    output.flush().map_err(|_| "cannot flush source capture")?;
    Ok(())
}
fn apk(path: &Path) -> Result<Files> {
    let mut child = std::process::Command::new("gzip")
        .arg("-dc")
        .arg(path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| "cannot decode source APK")?;
    let stream = child.stdout.take().ok_or("missing source decoder stream")?;
    let result = inspect(BufReader::new(stream));
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| "source decoder cleanup failed")?;
    let files = result?;
    if !status.success() {
        return Err("source APK decoding failed");
    }
    Ok(files)
}

#[test]
#[ignore = "fixed native arm64 image/APK/source captures; proposals only; no extraction or execution"]
fn inspect_current_git_and_glibc_corresponding_sources() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let input = root.join(".work/current-native-source");
    let native = input.join("gitleaks-arm64.tar");
    if hash(&native, 1024 * 1024 * 1024)?
        != "11a912d624d523c072a06a8e7b2b7a8e1a163d75e7d913e27cd5f873b4fc1f24"
    {
        return Err("changed native source observation");
    }
    let native = inspect(File::open(native).map_err(|_| "cannot open native image")?)?;
    let mut observations = Vec::new();
    for (origin, version, selected, binary_hash, source_hash) in [
        (
            "git",
            "2.56.1-r1",
            "usr/bin/git",
            "86983783d33873702dabf7baa835bd2537f4af05147fbdf0503a0080bb7e3e22",
            "a70aa18ac051d67f3e21fbcd1fb738fbe757cfd6035d9e6687e19d5b99f1ae96",
        ),
        (
            "glibc-2.44",
            "2.44-r19",
            "usr/lib/libc.so.6",
            "92db726acaa1c95edfe75db8f11cefc17eafcd26dac03e922e3f4820d1d8ee41",
            "c58a9f3a2d6148af133027d07902d953c83ff45e23057df0ae9f25ff3fbd0273",
        ),
    ] {
        let file_prefix = if origin == "git" { "git" } else { "glibc" };
        let binary_file = input.join(format!("{file_prefix}-arm64.apk"));
        let source_file = input.join(format!("{file_prefix}-source-arm64.apk"));
        if hash(&binary_file, 64 * 1024 * 1024)? != binary_hash
            || hash(&source_file, 128 * 1024 * 1024)? != source_hash
        {
            return Err("changed supplier source capture");
        }
        let binary = apk(&binary_file)?;
        let source = apk(&source_file)?;
        let info = std::str::from_utf8(
            binary
                .texts
                .get(".PKGINFO")
                .ok_or("missing package identity")?,
        )
        .map_err(|_| "invalid package identity")?;
        if !info.lines().any(|l| l == format!("pkgver = {version}"))
            || !info.lines().any(|l| l == format!("origin = {origin}"))
        {
            return Err("foreign supplier package version/origin");
        }
        let selected_hash = binary
            .hashes
            .get(selected)
            .ok_or("supplier omitted selected native payload")?;
        if native.hashes.get(selected) != Some(selected_hash) {
            return Err("supplier payload differs from native image");
        }
        let manifest = binary
            .texts
            .get(".source.sha256")
            .ok_or("missing binary-bound source manifest")?;
        if source
            .texts
            .get(&format!("usr/src/{origin}/SOURCES.sha256"))
            != Some(manifest)
        {
            return Err("source companion manifest differs from binary");
        }
        let mut count = 0;
        for line in std::str::from_utf8(manifest)
            .map_err(|_| "invalid source manifest")?
            .lines()
        {
            let (expected, relative) =
                line.split_once("  ").ok_or("invalid source checksum row")?;
            if expected.len() != 64
                || !expected.bytes().all(|b| b.is_ascii_hexdigit())
                || relative.is_empty()
                || Path::new(relative)
                    .components()
                    .any(|p| !matches!(p, Component::Normal(_)))
            {
                return Err("invalid source checksum path/hash");
            }
            if source
                .hashes
                .get(&format!("usr/src/{origin}/{relative}"))
                .map(String::as_str)
                != Some(expected)
            {
                return Err("source companion file differs from binary manifest");
            }
            count += 1;
        }
        if count == 0 {
            return Err("empty source companion manifest");
        }
        observations.push(json!({"origin":origin,"version":version,"arch":"arm64","binary_apk_sha256":binary_hash,"source_apk_sha256":source_hash,"selected_native_path":selected,"selected_native_sha256":selected_hash,"verified_source_files":count,"signature_verification":"not-established; standalone APK verify reported UNTRUSTED","independent_rebuild":false}));
    }
    let output = input.join("source-observation.json");
    if output.exists() {
        return Err("refusing existing source observation");
    }
    write_json(
        &output,
        &json!({"schema":1,"observations":observations,"all_runtime_packages_covered":false,"both_architectures_covered":false,"redistribution_approved":false,"trust":"HTTPS supplier and selected native payload identity; not independent build or package signature proof"}),
    )?;
    let check = read_json(&output)?;
    if check["redistribution_approved"] != false {
        return Err("source observation is not approval");
    }
    Ok(())
}

#[test]
#[ignore = "fixed dual-native run43753305153; HTTPS APK/source collection proposal, never approval"]
fn collect_current_gitleaks_native_sources_and_profile() -> Result<()> {
    use crate::release::{mkdir, text};
    use serde_json::Value;
    use std::collections::BTreeSet;
    const SOURCE: &str = "8f3e46e8f4919a106ef0040b5daf1502fc5c20d2";
    let mut driver = crate::Driver::new()?;
    let root = driver.root.clone();
    let output = root.join(".work/gitleaks-current-source-proposal");
    mkdir(&output, false)?;
    let mut reference = None;
    let mut observations = Vec::new();
    let mut captures = Vec::new();
    for (arch, supplier_arch, expected) in [
        (
            "amd64",
            "x86_64",
            "6ded750d8b861eb42e569fedf8b3335fea280ed00837dff3b5b97c8ced681728",
        ),
        (
            "arm64",
            "aarch64",
            "b8463ee90a93ac82e34ab893fe339db90863c50483614426fd6885cbe1eb8e6e",
        ),
    ] {
        let input = root.join(format!(
            ".work/gitleaks-current-captures/{arch}/gitleaks.syft.json"
        ));
        if hash(&input, 8 * 1024 * 1024)? != expected {
            return Err("changed native Gitleaks capture");
        }
        let doc = read_json(&input)?;
        let metadata = &doc["source"]["metadata"];
        if metadata["architecture"] != arch
            || metadata["os"] != "linux"
            || metadata["labels"]["org.opencontainers.image.revision"] != SOURCE
            || metadata["labels"]["org.opencontainers.image.source"]
                != "https://github.com/PRJXAI/devsecops"
        {
            return Err("foreign native Gitleaks source");
        }
        let mut locations = BTreeMap::<String, BTreeSet<Vec<String>>>::new();
        let mut compilers = BTreeMap::<String, String>::new();
        let mut native_files = BTreeMap::<String, Vec<String>>::new();
        for file in doc["files"]
            .as_array()
            .ok_or("missing native file observations")?
        {
            if file["metadata"]["type"] != "RegularFile" {
                continue;
            }
            for digest in file["digests"]
                .as_array()
                .ok_or("missing native file digests")?
            {
                if digest["algorithm"] == "sha256" {
                    native_files
                        .entry(text(digest, "/value")?.into())
                        .or_default()
                        .push(text(&file["location"], "/path")?.into());
                }
            }
        }
        let arch_output = output.join(arch);
        mkdir(&arch_output, false)?;
        let mut sources = BTreeMap::<String, Files>::new();
        let mut package_count = 0;
        for package in doc["artifacts"]
            .as_array()
            .ok_or("missing native packages")?
        {
            let row = ["type", "name", "version", "foundBy"]
                .into_iter()
                .map(|key| text(package, &format!("/{key}")).map(str::to_owned))
                .collect::<Result<Vec<_>>>()?;
            if row[2].eq_ignore_ascii_case("UNKNOWN") {
                return Err("unknown native package");
            }
            for location in package["locations"]
                .as_array()
                .ok_or("missing native locations")?
            {
                let path = text(location, "/path")?.to_owned();
                locations
                    .entry(path.clone())
                    .or_default()
                    .insert(row.clone());
                if package["type"] == "go-module" {
                    if package["metadata"]["goCompiledVersion"] != "go1.27.4" {
                        return Err("foreign native Go compiler");
                    }
                    compilers.insert(path, "go1.27.4".into());
                }
            }
            if package["type"] != "apk" {
                continue;
            }
            let name = text(package, "/name")?;
            let version = text(package, "/version")?;
            let origin = package["metadata"]["originPackage"]
                .as_str()
                .or({
                    // The ELF cataloger attributes only the three deliberately copied
                    // Git-stage files, not an installed database entry. Verify the
                    // exact source-origin mapping against the downloaded APK below.
                    match name {
                        "git" => Some("git"),
                        "pcre2" => Some("pcre2"),
                        "zlib" => Some("zlib"),
                        _ => None,
                    }
                })
                .ok_or("missing reviewed native APK origin")?;
            if ![
                "ca-certificates-bundle",
                "git",
                "glibc-2.44",
                "glibc-2.44-locale-posix",
                "ld-linux-2.44",
                "libgcc",
                "libstdc++",
                "pcre2",
                "wolfi-baselayout",
                "zlib",
            ]
            .contains(&name)
                || [name, version, origin].iter().any(|value| {
                    value.is_empty()
                        || !value
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-._+".contains(&b))
                })
            {
                return Err("unreviewed native APK package coordinate");
            }
            let binary_path = arch_output.join(format!("{name}-{version}.apk"));
            let source_path = arch_output.join(format!("{origin}-source-{version}.apk"));
            // CA's exact companion returned 404. Its editable PEM source form
            // needs separate native-byte/legal review, not an invented companion.
            if origin == "ca-certificates" {
                observations.push(json!({"arch":arch,"package":name,"version":version,"origin":origin,"status":"BLOCKED: exact preferred-source/legal review pending; no source companion inferred"}));
                package_count += 1;
                continue;
            }
            for (file, coordinate) in [
                (&binary_path, format!("{name}-{version}")),
                (&source_path, format!("{origin}-source-{version}")),
            ] {
                if file.exists() {
                    continue;
                }
                if coordinate == "gcc-source-16.2.0-r4" {
                    collect_gcc_ranges(&mut driver, file, supplier_arch)?;
                    continue;
                }
                let url =
                    format!("https://apk.cgr.dev/chainguard/{supplier_arch}/{coordinate}.apk");
                let mut command = std::process::Command::new("/usr/bin/curl");
                command
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .args([
                        "--disable",
                        "--fail",
                        "--silent",
                        "--show-error",
                        "--location",
                        "--proto",
                        "=https",
                        "--proto-redir",
                        "=https",
                        "--max-time",
                        "180",
                        "--max-filesize",
                        "134217728",
                        "--output",
                    ])
                    .arg(file)
                    .arg(url);
                driver.execute(command, 190, false, 0)?;
            }
            let binary = apk(&binary_path)?;
            if !sources.contains_key(origin) {
                sources.insert(origin.into(), apk(&source_path)?);
            }
            let source = &sources[origin];
            let info = std::str::from_utf8(
                binary
                    .texts
                    .get(".PKGINFO")
                    .ok_or("missing binary package identity")?,
            )
            .map_err(|_| "invalid package info")?;
            for line in [
                format!("pkgname = {name}"),
                format!("pkgver = {version}"),
                format!("origin = {origin}"),
                format!("arch = {supplier_arch}"),
            ] {
                if !info.lines().any(|v| v == line) {
                    return Err("binary package identity differs from native capture");
                }
            }
            let manifest = binary
                .texts
                .get(".source.sha256")
                .ok_or("binary APK has no corresponding source manifest")?;
            if source
                .texts
                .get(&format!("usr/src/{origin}/SOURCES.sha256"))
                != Some(manifest)
            {
                return Err("source companion differs from native binary manifest");
            }
            let mut count = 0;
            for line in std::str::from_utf8(manifest)
                .map_err(|_| "invalid source checksums")?
                .lines()
            {
                let (checksum, relative) =
                    line.split_once("  ").ok_or("invalid source checksum")?;
                if checksum.len() != 64
                    || !checksum.bytes().all(|b| b.is_ascii_hexdigit())
                    || relative.is_empty()
                    || Path::new(relative)
                        .components()
                        .any(|p| !matches!(p, Component::Normal(_)))
                    || source
                        .hashes
                        .get(&format!("usr/src/{origin}/{relative}"))
                        .map(String::as_str)
                        != Some(checksum)
                {
                    return Err("source companion checksum mismatch");
                }
                count += 1;
            }
            if count == 0 {
                return Err("empty source manifest");
            }
            let bindings: Vec<Value> = binary
                .hashes
                .iter()
                .filter_map(|(path, digest)| {
                    native_files.get(digest).map(
                        |native| json!({"apk_path":path,"native_paths":native,"sha256":digest}),
                    )
                })
                .collect();
            if bindings.is_empty() {
                return Err("no actual native payload bytes match supplier APK");
            }
            observations.push(json!({"arch":arch,"package":name,"version":version,"origin":origin,"binary_apk_sha256":hash(&binary_path,128*1024*1024)?,"source_apk_sha256":hash(&source_path,1024*1024*1024)?,"source_file":source_path.strip_prefix(&output).map_err(|_| "escaping source output")?,"source_manifest_files":count,"native_payload_bindings":bindings,"license":info.lines().find_map(|l| l.strip_prefix("license = ")).ok_or("missing package license")?,"signature_verified":false}));
            package_count += 1;
        }
        if package_count != 10 {
            return Err("native runtime package set changed");
        }
        let profile = json!({"locations":locations,"compilers":compilers});
        if reference.as_ref().is_some_and(|old| *old != profile) {
            return Err("native Gitleaks profiles differ");
        }
        reference = Some(profile);
        captures.push(json!({"arch":arch,"source_sha":SOURCE,"run":43753305153u64,"sbom_sha256":expected,"config_id":metadata["imageID"]}));
    }
    let mut profile = reference.ok_or("missing native Gitleaks profile")?;
    profile["catalog"] = json!("captured");
    profile["evidence"] =
        json!({"captures":captures,"release_accepted":false,"vulnerability_scan":"not-run"});
    write_json(&output.join("proposed-gitleaks-production.json"), &profile)?;
    write_json(
        &output.join("source-observation.json"),
        &json!({"schema":1,"observations":observations,"both_native_catalogs_verified":true,"redistribution_approved":false,"signature_verification":"not-established; HTTPS/hash/native-byte-bound source observations only","recipient_delivery":"not-yet-implemented"}),
    )
}
