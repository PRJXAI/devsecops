//! Fixed accompanying-source delivery for the current native Gitleaks runtime.
//! No caller-supplied packages, source endpoints, commands or approval switches.
use super::{Driver, Result};
use crate::release::{bytes, hash, mkdir, read_json, write_new};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::Command,
};

pub(crate) struct Source {
    pub name: &'static str,
    pub sha256: &'static str,
    pub bytes: u64,
}
pub(crate) fn sources(arch: &str) -> Result<Vec<Source>> {
    let names = [
        "gcc-source-16.2.0-r4.apk",
        "git-source-2.56.1-r1.apk",
        "glibc-2.44-source-2.44-r19.apk",
        "wolfi-baselayout-source-20230201-r31.apk",
    ];
    let (hashes, sizes) = match arch {
        "amd64" => (
            [
                "12f55cbe6af7174f03460dc14d62c383a29e3e0da70fcda4cedac987592678af",
                "4de71c71249c08ab270e72ae7d143aa58ec58c931febdab6915f18f28d31696d",
                "c674cadf778e5492a075e28beee2eee97bf4ec5c3496516701ba1c167f1a06f8",
                "a1da40cd4aed275f2111feffda51752a3c6890c65b84eea82e4794816debf111",
            ],
            [168507271, 13001163, 41786886, 15462],
        ),
        "arm64" => (
            [
                "07564e47fb603301ee2cc0647a57ddb44363926a09233b85755178f22f0270e4",
                "a70aa18ac051d67f3e21fbcd1fb738fbe757cfd6035d9e6687e19d5b99f1ae96",
                "c58a9f3a2d6148af133027d07902d953c83ff45e23057df0ae9f25ff3fbd0273",
                "902fc22a76f11e1a5a0cf9960196c91137fa5ece6d1bafca8126f3ff2b1bbabe",
            ],
            [168507355, 13001239, 41786963, 15520],
        ),
        _ => return Err("unsupported native corresponding-source architecture"),
    };
    Ok(names
        .into_iter()
        .zip(hashes)
        .zip(sizes)
        .map(|((name, sha256), bytes)| Source {
            name,
            sha256,
            bytes,
        })
        .collect())
}
pub(crate) fn notice(root: &Path) -> Result<Vec<u8>> {
    let file = root.join("licenses/gitleaks-runtime-NOTICES.txt");
    if hash(&file, 1024 * 1024)?
        != "505907d7c7178d6b75e9a9e6f67f4b0e8b232b7772433a3f6596c8f2b56158c9"
    {
        return Err("native Gitleaks notices differ from reviewed material");
    }
    bytes(&file, 1024 * 1024)
}
pub(crate) fn index(root: &Path) -> Result<Vec<u8>> {
    let file = root.join("licenses/gitleaks-runtime-source-index.json");
    if hash(&file, 1024 * 1024)?
        != "73b24b710a28791a73461dfd7be36d3a892670a28642a1a52c9746e989bfb67e"
    {
        return Err("native Gitleaks source index differs from captured material");
    }
    bytes(&file, 1024 * 1024)
}

pub(crate) fn verify_archive(path: &Path) -> Result<()> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => return Err("unsupported source contract architecture"),
    };
    let mut expected: Vec<(String, String, u64)> = sources(arch)?
        .into_iter()
        .map(|source| {
            (
                format!(
                    "usr/share/licenses/gitleaks/corresponding-source/{}",
                    source.name
                ),
                source.sha256.to_owned(),
                source.bytes,
            )
        })
        .collect();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (name, data) in [
        ("NATIVE-NOTICES.txt", notice(root)?),
        ("SOURCE-INDEX.json", index(root)?),
    ] {
        use sha2::Digest;
        expected.push((
            format!("usr/share/licenses/gitleaks/{name}"),
            sha2::Sha256::digest(&data)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            data.len() as u64,
        ));
    }
    verify_files(path, &expected)
}
fn verify_files(path: &Path, expected: &[(String, String, u64)]) -> Result<()> {
    use sha2::Digest;
    let mut archive = tar::Archive::new(
        crate::release::regular(path, crate::filesystem::ARCHIVE)?
            .take(crate::filesystem::ARCHIVE + 1),
    );
    let mut found = std::collections::BTreeSet::new();
    for (n, entry) in archive
        .entries()
        .map_err(|_| "invalid source contract archive")?
        .raw(true)
        .enumerate()
    {
        if n >= 4096 {
            return Err("source contract header limit");
        }
        let mut entry = entry.map_err(|_| "invalid source contract member")?;
        let name = entry
            .path()
            .map_err(|_| "invalid source member path")?
            .to_str()
            .ok_or("invalid source member text")?
            .to_owned();
        let record = expected.iter().find(|(path, _, _)| path == &name);
        if let Some((_, digest, size)) = record {
            if !found.insert(name)
                || !entry.header().entry_type().is_file()
                || entry.size() != *size
                || entry.header().mode().map_err(|_| "invalid source mode")? != 0o444
            {
                return Err("source archive type/size/mode/uniqueness mismatch");
            }
            let mut hash = sha2::Sha256::new();
            let mut buffer = [0u8; 65536];
            loop {
                let n = entry
                    .read(&mut buffer)
                    .map_err(|_| "cannot hash accompanying source")?;
                if n == 0 {
                    break;
                }
                hash.update(&buffer[..n]);
            }
            let actual: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
            if &actual != digest {
                return Err("packaged native source differs from reviewed bytes");
            }
        } else if name.starts_with("usr/share/licenses/gitleaks/corresponding-source/")
            && !entry.header().entry_type().is_dir()
        {
            return Err("foreign accompanying-source member");
        }
    }
    if found.len() != expected.len() {
        return Err("missing accompanying-source/native-notice material");
    }
    Ok(())
}

pub(crate) fn install(driver: &mut Driver, context: &Path) -> Result<()> {
    let arch = driver.native()?.0;
    let supplier_arch = if arch == "amd64" { "x86_64" } else { "aarch64" };
    let source_folder = context.join("sources");
    mkdir(&source_folder, false)?;
    let records = sources(arch)?;
    if records.iter().map(|r| r.bytes).sum::<u64>() > 512 * 1024 * 1024 {
        return Err("corresponding-source aggregate budget exceeded");
    }
    let material = read_json(
        &driver
            .root
            .join("licenses/gitleaks-runtime-source-index.json"),
    )?;
    for record in records {
        let captured = material["native_source_observations"]["observations"]
            .as_array()
            .ok_or("missing native source observations")?
            .iter()
            .find(|row| {
                row["arch"] == arch && row["source_file"] == format!("{arch}/{}", record.name)
            })
            .ok_or("source archive omitted from both-native observations")?;
        if captured["source_apk_sha256"] != record.sha256
            || captured["source_manifest_files"]
                .as_u64()
                .is_none_or(|n| n == 0)
        {
            return Err("source archive differs from native manifest observation");
        }
        let file = source_folder.join(record.name);
        let url = format!(
            "https://apk.cgr.dev/chainguard/{supplier_arch}/{}",
            record.name
        );
        if record.bytes > 128 * 1024 * 1024 {
            // Three <=64 MiB transfers, exact Content-Range/length, bounded
            // aggregate; never lift the individual transport budget.
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&file)
                .map_err(|_| "cannot create source archive")?;
            let mut start = 0;
            while start < record.bytes {
                let end = (start + 64 * 1024 * 1024 - 1).min(record.bytes - 1);
                let part = driver.logs.join(format!("source-{arch}-{start}.part"));
                let headers = driver.logs.join(format!("source-{arch}-{start}.headers"));
                let mut command = Command::new("/usr/bin/curl");
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
                    .arg(&url);
                driver.execute(command, 190, false, 0)?;
                let raw = bytes(&headers, 16 * 1024)?;
                let raw = std::str::from_utf8(&raw)
                    .map_err(|_| "invalid source range response")?
                    .to_ascii_lowercase();
                if !raw.lines().any(|line| {
                    line.trim() == format!("content-range: bytes {start}-{end}/{}", record.bytes)
                }) || fs::metadata(&part)
                    .map_err(|_| "missing source partition")?
                    .len()
                    != end - start + 1
                {
                    return Err("source partition identity mismatch");
                }
                let mut input =
                    crate::release::regular(&part, 64 * 1024 * 1024)?.take(64 * 1024 * 1024 + 1);
                if std::io::copy(&mut input, &mut output)
                    .map_err(|_| "cannot stream source partition")?
                    != end - start + 1
                {
                    return Err("incomplete source partition");
                }
                start = end + 1;
            }
            output.flush().map_err(|_| "cannot flush source archive")?;
        } else {
            let mut command = Command::new("/usr/bin/curl");
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
                .arg(&file)
                .arg(&url);
            driver.execute(command, 190, false, 0)?;
        }
        if crate::release::regular(&file, 512 * 1024 * 1024)?
            .metadata()
            .map_err(|_| "cannot inspect source archive")?
            .len()
            != record.bytes
            || hash(&file, 512 * 1024 * 1024)? != record.sha256
        {
            return Err("source archive identity mismatch");
        }
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o444))
            .map_err(|_| "cannot seal accompanying source")?;
    }
    write_new(
        &context.join("native-notices.txt"),
        &notice(&driver.root)?,
        0o444,
    )?;
    write_new(
        &context.join("source-index.json"),
        &index(&driver.root)?,
        0o444,
    )
}

#[cfg(test)]
#[path = "gitleaks_runtime_tests.rs"]
mod tests;
