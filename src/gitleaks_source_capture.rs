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
        if size > 128 * 1024 * 1024 || total > 1024 * 1024 * 1024 || hashes.len() >= 100_000 {
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
    if !status.success() {
        return Err("source APK decoding failed");
    }
    result
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
