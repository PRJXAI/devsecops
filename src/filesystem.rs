//! Inspect a stopped container's merged files, never execute a tool or shell.
//! Export's post-write size check is NOT a host-disk quota (D4).
use super::{Driver, Result, release};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::atomic::Ordering,
};

const ARCHIVE: u64 = 1024 * 1024 * 1024;
const MEMBER: u64 = 512 * 1024 * 1024;
const HEADERS: usize = 4096;
const CA: &str = "etc/ssl/certs/ca-certificates.crt";

fn entrypoint(tool: &str) -> Result<Vec<String>> {
    if !super::TOOLS.contains(&tool) {
        return Err("unsupported filesystem contract");
    }
    let mut args = vec![format!("/usr/local/bin/{tool}")];
    if tool == "cargo-audit" {
        args.push("audit".into());
    }
    Ok(args)
}

fn effective(data: &[u8], expected: &[String]) -> Result<()> {
    (serde_json::from_slice::<Vec<String>>(data).ok().as_deref() == Some(expected))
        .then_some(())
        .ok_or("unexpected effective image entrypoint")
}

pub(super) fn check(driver: &mut Driver, tool: &str, image: &str) -> Result<()> {
    let expected = entrypoint(tool)?;
    if !image.strip_prefix("sha256:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return Err("filesystem check requires immutable image identity");
    }
    let format = "{{json .Config.Entrypoint}}";
    let inspected = driver.docker(&["image", "inspect", "--format", format, image], 30, false)?;
    effective(&release::bytes(&inspected, 4096)?, &expected)?;
    driver.sequence = driver
        .sequence
        .checked_add(1)
        .ok_or("filesystem sequence exhausted")?;
    let run = driver
        .logs
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("missing filesystem run identity")?;
    let name = format!("filesystem-{run}-{}", driver.sequence);
    let path = driver
        .logs
        .join(format!("filesystem-{}.tar", driver.sequence));
    // Docker truncates this precreated private file; its parent is driver-private.
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| "cannot create private filesystem export")?;
    let output = path.to_str().ok_or("invalid filesystem export path")?;
    let mut create: Vec<_> = "create --pull=never --network=none --read-only --user=65532:65532 --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=64 --memory=256m --memory-swap=256m --cpus=1".split_ascii_whitespace().collect();
    create.extend(["--name", &name, image]);
    let result = driver
        .docker(&create, 30, false)
        .and_then(|_| driver.docker(&["export", "--output", output, &name], 120, false));
    // Unconditional and cancellation-ignoring, even after create/export failure.
    let cleanup = driver.docker(&["rm", "--force", &name], 15, true);
    super::container_output(result, cleanup)?;
    files(&path, tool)?;
    if driver.cancelled.load(Ordering::Relaxed) {
        return Err("check cancelled");
    }
    Ok(())
}

fn safe(name: &[u8], directory: bool) -> Result<String> {
    let name = std::str::from_utf8(name).map_err(|_| "invalid filesystem path")?;
    let name = if directory {
        name.strip_suffix('/').unwrap_or(name)
    } else {
        name
    };
    if name.is_empty()
        || name.len() > 256
        || !name
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"\\:".contains(&b))
        || name.split('/').any(|s| matches!(s, "" | "." | ".."))
    {
        return Err("unsafe filesystem path");
    }
    Ok(name.into())
}

fn forbidden(path: &str) -> bool {
    // Executable names, including target/version-prefixed compilers; not APK
    // metadata, notices, libgcc_s or libstdc++. Symlink aliases count too.
    let names = "sh ash bash dash zsh ksh fish csh tcsh busybox apk apk.static apt dpkg rpm yum dnf microdnf pacman npm npx pip pip3 pipx gem bundle bundler brew uv conda mamba nix cargo rustc rustup gcc g++ cc c++ clang clang++ go javac gfortran cc1 cc1plus tcc zig flang swiftc";
    let basename = path.rsplit('/').next().unwrap_or(path);
    !matches!(basename, "cargo-audit" | "cargo-deny")
        && basename
            .split('-')
            .any(|part| names.split_ascii_whitespace().any(|name| part == name))
}

fn required(tool: &str) -> Result<Vec<String>> {
    let mut paths = vec![
        CA.into(),
        entrypoint(tool)?[0].trim_start_matches('/').into(),
    ];
    let closure = match tool {
        "docker" => {
            "usr/local/libexec/docker/cli-plugins/docker-compose usr/local/libexec/docker/cli-plugins/docker-buildx"
        }
        "kind" => "usr/local/bin/docker",
        "gitleaks" => "usr/bin/git usr/lib/libc.so.6 usr/lib/libpcre2-8.so.0 usr/lib/libz.so.1",
        _ => "",
    };
    paths.extend(closure.split_ascii_whitespace().map(String::from));
    if tool == "gitleaks" {
        // glibc-dynamic base: confirmed regular native objects, not /lib aliases.
        let loader = if cfg!(target_arch = "aarch64") {
            "usr/lib/ld-linux-aarch64.so.1"
        } else {
            "usr/lib/ld-linux-x86-64.so.2"
        };
        paths.push(loader.into());
    }
    Ok(paths)
}

fn elf(header: &[u8]) -> bool {
    let machine: u16 = if cfg!(target_arch = "aarch64") {
        183
    } else {
        62
    };
    header.len() == 64
        && &header[..7] == b"\x7fELF\x02\x01\x01"
        && matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3)
        && header[18..20] == machine.to_le_bytes()
        && header[20..24] == 1u32.to_le_bytes()
        && header[52..54] == 64u16.to_le_bytes()
}

fn files(path: &Path, tool: &str) -> Result<()> {
    let required = required(tool)?;
    let mut input = release::regular(path, ARCHIVE)?.take(ARCHIVE + 1);
    let (mut seen, mut found) = (BTreeMap::new(), BTreeSet::new());
    let mut end = 0;
    {
        let mut archive = tar::Archive::new(&mut input);
        let entries = archive
            .entries()
            .map_err(|_| "cannot read filesystem headers")?;
        for (count, entry) in entries.raw(true).enumerate() {
            if count >= HEADERS {
                return Err("filesystem header budget exceeded");
            }
            let mut entry = entry.map_err(|_| "invalid filesystem archive")?;
            let h = entry.header();
            let kind = h.entry_type();
            let name = safe(&entry.path_bytes(), kind.is_dir())?;
            // Exactly the four devices observed in native base-image exports.
            let device = kind.is_character_special()
                && h.device_major().ok().flatten() == Some(1)
                && matches!(
                    (name.as_str(), h.device_minor().ok().flatten()),
                    ("dev/null", Some(3))
                        | ("dev/zero", Some(5))
                        | ("dev/random", Some(8))
                        | ("dev/urandom", Some(9))
                );
            // Raw iteration: no PAX/GNU/sparse allocations or hardlink resolution.
            if !kind.is_file() && !kind.is_dir() && !kind.is_symlink() && !device {
                return Err("unsupported filesystem member type");
            }
            let size = entry.size();
            if size > MEMBER || (!kind.is_file() && size != 0) {
                return Err("filesystem member budget exceeded");
            }
            end = entry
                .raw_file_position()
                .checked_add(size.div_ceil(512) * 512)
                .filter(|n| *n <= ARCHIVE - 1024)
                .ok_or("filesystem archive budget exceeded")?;
            if seen.insert(name.clone(), kind.is_dir()).is_some() {
                return Err("duplicate filesystem path");
            }
            let mode = h.mode().map_err(|_| "invalid filesystem mode")?;
            if (kind.is_file() && mode & 0o111 != 0 || kind.is_symlink()) && forbidden(&name) {
                return Err("forbidden filesystem executable");
            }
            if kind.is_symlink() {
                let target = entry
                    .link_name_bytes()
                    .ok_or("missing filesystem link target")?;
                let target =
                    std::str::from_utf8(&target).map_err(|_| "invalid filesystem link target")?;
                if target.is_empty()
                    || target.len() > 256
                    || target
                        .bytes()
                        .any(|b| !b.is_ascii_graphic() || b"\\:".contains(&b))
                {
                    return Err("unsafe filesystem link target");
                }
                let mut depth = if target.starts_with('/') {
                    0
                } else {
                    name.matches('/').count()
                };
                for part in target.split('/') {
                    match part {
                        "" | "." => (),
                        ".." => depth = depth.checked_sub(1).ok_or("escaping filesystem link")?,
                        _ => depth += 1,
                    }
                }
                if forbidden(target) {
                    return Err("forbidden filesystem executable alias");
                }
            } else if entry.link_name_bytes().is_some() {
                return Err("unexpected filesystem link target");
            }
            if required.contains(&name) {
                if !kind.is_file() || size == 0 {
                    return Err("critical filesystem file must be regular");
                }
                if name == CA {
                    if size > 1024 * 1024 {
                        return Err("CA bundle budget exceeded");
                    }
                    let mut pem = String::new();
                    entry
                        .read_to_string(&mut pem)
                        .map_err(|_| "invalid CA bundle")?;
                    if !pem.contains("-----BEGIN CERTIFICATE-----\n")
                        || !pem.contains("-----END CERTIFICATE-----")
                    {
                        return Err("missing CA PEM certificates");
                    }
                } else {
                    let mut header = [0; 64];
                    entry
                        .read_exact(&mut header)
                        .map_err(|_| "truncated critical ELF file")?;
                    if !elf(&header)
                        || ((!name.starts_with("usr/lib/") || name.contains("/ld-linux-"))
                            && mode & 0o111 == 0)
                    {
                        return Err("critical file is not a native ELF payload");
                    }
                }
                found.insert(name);
            }
        }
    }
    // Reject truncation/hidden concatenated archives after tar's first zero block.
    let mut consumed = ARCHIVE + 1 - input.limit();
    if consumed != end + 512 {
        return Err("missing filesystem end marker");
    }
    let mut buffer = [0; 32768];
    loop {
        let n = input
            .read(&mut buffer)
            .map_err(|_| "cannot read filesystem trailer")?;
        if n == 0 {
            break;
        }
        consumed += n as u64;
        if consumed > ARCHIVE || buffer[..n].iter().any(|b| *b != 0) {
            return Err("invalid filesystem trailer");
        }
    }
    if consumed < end + 1024 || !consumed.is_multiple_of(512) {
        return Err("truncated filesystem trailer");
    }
    if required.iter().any(|p| {
        !found.contains(p)
            || p.match_indices('/')
                .any(|(i, _)| seen.get(&p[..i]) == Some(&false))
    }) {
        return Err("missing or aliased critical filesystem file");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Write, os::unix::fs::PermissionsExt};
    use tar::{EntryType, Header};

    fn payload() -> Vec<u8> {
        let mut data = vec![0; 64];
        data[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        data[16..18].copy_from_slice(&2u16.to_le_bytes());
        data[18..20].copy_from_slice(
            &(if cfg!(target_arch = "aarch64") {
                183u16
            } else {
                62u16
            })
            .to_le_bytes(),
        );
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        data[52..54].copy_from_slice(&64u16.to_le_bytes());
        data
    }

    fn header(name: &str, kind: EntryType, size: u64) -> Header {
        let mut h = Header::new_ustar();
        // Deliberately permit unsafe names for negative fixtures.
        h.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        h.set_entry_type(kind);
        h.set_mode(0o755);
        h.set_size(size);
        h.set_cksum();
        h
    }

    fn fixture(
        tool: &str,
        omit: &str,
        extra: Option<(&str, EntryType, &[u8])>,
    ) -> (Driver, std::path::PathBuf) {
        let driver = Driver::new().unwrap();
        let path = driver.logs.join("synthetic.tar");
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let mut tar = tar::Builder::new(file);
        for name in required(tool)
            .unwrap()
            .iter()
            .filter(|p| p.as_str() != omit)
        {
            let data = if name == CA {
                b"-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n".to_vec()
            } else {
                payload()
            };
            tar.append(
                &header(name, EntryType::Regular, data.len() as u64),
                data.as_slice(),
            )
            .unwrap();
        }
        if let Some((name, kind, data)) = extra {
            let mut h = header(
                name,
                kind,
                if kind.is_symlink() {
                    0
                } else {
                    data.len() as u64
                },
            );
            if kind.is_symlink() {
                h.set_link_name(std::str::from_utf8(data).unwrap()).unwrap();
                h.set_cksum();
            }
            tar.append(&h, if kind.is_symlink() { &[][..] } else { data })
                .unwrap();
        }
        tar.finish().unwrap();
        (driver, path)
    }

    #[test]
    fn exact_entrypoints_for_all_nine() {
        for (tool, expected) in [
            ("syft", vec!["/usr/local/bin/syft"]),
            ("grype", vec!["/usr/local/bin/grype"]),
            ("gitleaks", vec!["/usr/local/bin/gitleaks"]),
            ("cargo-audit", vec!["/usr/local/bin/cargo-audit", "audit"]),
            ("cargo-deny", vec!["/usr/local/bin/cargo-deny"]),
            ("kind", vec!["/usr/local/bin/kind"]),
            ("kustomize", vec!["/usr/local/bin/kustomize"]),
            ("kubectl", vec!["/usr/local/bin/kubectl"]),
            ("docker", vec!["/usr/local/bin/docker"]),
        ] {
            assert_eq!(entrypoint(tool).unwrap(), expected);
        }
        let mut driver = Driver::new().unwrap();
        for mutable in ["syft:latest", "", "sha256:short"] {
            assert!(check(&mut driver, "syft", mutable).is_err());
        }
        assert_eq!(driver.sequence, 0);

        for tool in super::super::TOOLS {
            let expected = entrypoint(tool).unwrap();
            effective(&serde_json::to_vec(&expected).unwrap(), &expected).unwrap();
            for bad in [
                b"null".as_slice(),
                b"[]",
                b"[\"sh\",\"-c\"]",
                b"[\"/usr/local/bin/docker\",\"extra\"]",
            ] {
                assert!(effective(bad, &expected).is_err());
            }
        }
        assert_eq!(
            entrypoint("cargo-audit").unwrap(),
            ["/usr/local/bin/cargo-audit", "audit"]
        );
        assert!(
            effective(
                b"[\"/usr/local/bin/cargo-audit\"]",
                &entrypoint("cargo-audit").unwrap()
            )
            .is_err()
        );
        assert!(entrypoint("../syft").is_err());
    }

    #[test]
    fn all_payloads_and_each_distinct_closure_file_are_required() {
        for tool in super::super::TOOLS {
            let (_driver, path) = fixture(tool, "", None);
            files(&path, tool).unwrap();
            for missing in required(tool).unwrap() {
                let (_driver, path) = fixture(tool, &missing, None);
                assert!(files(&path, tool).is_err(), "{tool}: missing critical file");
                let (_driver, path) = fixture(
                    tool,
                    &missing,
                    Some((&missing, EntryType::Symlink, b"/elsewhere")),
                );
                assert!(files(&path, tool).is_err(), "{tool}: aliased critical file");
            }
        }
    }

    #[test]
    fn rejects_non_elf_foreign_elf_empty_or_invalid_ca_and_nonexecutables() {
        let mut foreign = payload();
        foreign[18..20].copy_from_slice(&0u16.to_le_bytes());
        for data in [b"not ELF".as_slice(), &foreign, &[]] {
            let (_driver, path) = fixture(
                "syft",
                "usr/local/bin/syft",
                Some(("usr/local/bin/syft", EntryType::Regular, data)),
            );
            assert!(files(&path, "syft").is_err());
        }
        for ca in [b"".as_slice(), b"not PEM", b"-----BEGIN CERTIFICATE-----\n"] {
            let (_driver, path) = fixture("syft", CA, Some((CA, EntryType::Regular, ca)));
            assert!(files(&path, "syft").is_err());
        }
        let (_driver, path) = fixture("syft", "", None);
        // CA occupies the first 1024 bytes; clear executable bits in the payload header.
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(1024)).unwrap();
        let mut h = header("usr/local/bin/syft", EntryType::Regular, 64);
        h.set_mode(0o644);
        h.set_cksum();
        file.write_all(h.as_bytes()).unwrap();
        assert!(files(&path, "syft").is_err());
    }

    #[test]
    fn forbidden_executables_and_aliases_but_not_metadata_or_runtime_libraries() {
        for name in [
            "bin/sh",
            "usr/bin/apk",
            "usr/bin/apt-get",
            "usr/bin/rustc",
            "usr/bin/x86_64-linux-gnu-gcc-14",
            "bin/busybox",
        ] {
            for kind in [EntryType::Regular, EntryType::Symlink] {
                let (_driver, path) = fixture("syft", "", Some((name, kind, b"/elsewhere")));
                assert!(files(&path, "syft").is_err());
            }
        }
        let (_driver, path) = fixture(
            "syft",
            "",
            Some(("usr/bin/alias", EntryType::Symlink, b"/bin/sh")),
        );
        assert!(files(&path, "syft").is_err());
        for name in [
            "lib/apk/db/installed",
            "usr/lib/libgcc_s.so.1",
            "usr/lib/libstdc++.so.6",
            "usr/share/licenses/bash/LICENSE",
        ] {
            let (_driver, path) = fixture(
                "syft",
                "",
                Some((name, EntryType::Regular, b"public fixture")),
            );
            files(&path, "syft").unwrap();
        }
    }

    #[test]
    fn only_observed_base_devices_are_permitted() {
        let (_driver, path) = fixture("syft", "", None);
        for (name, major, minor, accepted) in [
            ("dev/null", 1, 3, true),
            ("dev/zero", 1, 5, true),
            ("dev/random", 1, 8, true),
            ("dev/urandom", 1, 9, true),
            ("dev/null", 8, 3, false),
            ("dev/other", 1, 3, false),
        ] {
            let mut file = OpenOptions::new().write(true).open(&path).unwrap();
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::Start(2048)).unwrap();
            let mut h = header(name, EntryType::Char, 0);
            h.set_device_major(major).unwrap();
            h.set_device_minor(minor).unwrap();
            h.set_cksum();
            file.write_all(h.as_bytes()).unwrap();
            file.write_all(&[0; 1024]).unwrap();
            assert_eq!(files(&path, "syft").is_ok(), accepted);
        }
    }

    #[test]
    fn rejects_unsafe_duplicate_extension_and_ancestor_alias_members() {
        for (name, kind, data) in [
            ("../escape", EntryType::Regular, b"x".as_slice()),
            ("/absolute", EntryType::Regular, b"x"),
            ("a//b", EntryType::Regular, b"x"),
            ("a/./b", EntryType::Regular, b"x"),
            (CA, EntryType::Regular, b"duplicate"),
            ("extension", EntryType::XHeader, b"x"),
            ("sparse", EntryType::GNUSparse, b"x"),
            ("usr/local/bin/other", EntryType::Link, b""),
            ("usr/local", EntryType::Symlink, b"/elsewhere"),
            ("alias", EntryType::Symlink, b"../../escape"),
        ] {
            let (_driver, path) = fixture("syft", "", Some((name, kind, data)));
            assert!(files(&path, "syft").is_err());
        }
    }

    #[test]
    fn finite_archive_member_header_ca_and_trailer_budgets() {
        let (_driver, path) = fixture("syft", "", None);
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(ARCHIVE + 1).unwrap();
        assert!(files(&path, "syft").is_err());
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.write_all(header("oversized", EntryType::Regular, MEMBER + 1).as_bytes())
            .unwrap();
        assert_eq!(
            files(&path, "syft"),
            Err("filesystem member budget exceeded")
        );
        let mut tar = tar::Builder::new(
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .unwrap(),
        );
        for i in 0..=HEADERS {
            tar.append(
                &header(&format!("dir-{i}"), EntryType::Directory, 0),
                &[][..],
            )
            .unwrap();
        }
        tar.finish().unwrap();
        drop(tar);
        assert_eq!(
            files(&path, "syft"),
            Err("filesystem header budget exceeded")
        );
        let oversized_ca = vec![b'x'; 1024 * 1024 + 1];
        let (_driver, path) = fixture("syft", CA, Some((CA, EntryType::Regular, &oversized_ca)));
        assert_eq!(files(&path, "syft"), Err("CA bundle budget exceeded"));
        let (_driver, path) = fixture("syft", "", None);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"hidden")
            .unwrap();
        assert!(files(&path, "syft").is_err());
        let (_driver, path) = fixture("syft", "", None);
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(2560)
            .unwrap();
        assert!(files(&path, "syft").is_err());
    }

    #[test]
    #[ignore = "Rust subprocess fixture invoked by cleanup boundary test"]
    fn filesystem_check_failure_fixture() {
        let root = std::path::PathBuf::from(std::env::var_os("FILESYSTEM_FAKE_ROOT").unwrap());
        fs::write(root.join("pid"), std::process::id().to_string()).unwrap();
        let mode = std::env::var("FILESYSTEM_FAKE_MODE").unwrap();
        let mut driver = Driver::new().unwrap();
        let result = check(&mut driver, "syft", &format!("sha256:{}", "a".repeat(64)));
        assert!(result.is_err());
        if mode == "cleanup-fail" {
            assert_eq!(
                result,
                Err("check failed and container cleanup was not confirmed")
            );
        }
        if mode.ends_with("cancel") {
            assert!(driver.cancelled.load(std::sync::atomic::Ordering::Relaxed));
        }
        let commands = fs::read_to_string(root.join("commands")).unwrap();
        let commands: Vec<_> = commands.lines().collect();
        if mode == "entrypoint" {
            assert_eq!(commands.len(), 1);
        } else {
            assert!(commands[1].starts_with("create "));
            assert!(
                commands
                    .last()
                    .unwrap()
                    .starts_with("rm --force filesystem-")
            );
            let create: Vec<_> = commands[1].split_whitespace().collect();
            let name = create[create.iter().position(|s| *s == "--name").unwrap() + 1];
            assert_eq!(
                commands.last().unwrap().split_whitespace().last(),
                Some(name)
            );
            assert_eq!(
                commands.len(),
                if mode.starts_with("create-") { 3 } else { 4 }
            );
        }
    }

    #[test]
    fn cleanup_is_unconditional_after_create_export_failure_or_cancellation() {
        let mut driver = Driver::new().unwrap();
        let source = driver.logs.join("fake.rs");
        fs::write(&source, r#"
use std::{fs::OpenOptions, io::Write, process::{Command, Stdio}};
fn main() {
    let root = std::path::PathBuf::from(std::env::var_os("FILESYSTEM_FAKE_ROOT").unwrap());
    let mode = std::env::var("FILESYSTEM_FAKE_MODE").unwrap();
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mut log = OpenOptions::new().create(true).append(true).open(root.join("commands")).unwrap();
    writeln!(log, "{}", args.join(" ")).unwrap();
    match args[0].as_str() {
        "image" => println!("{}", if mode == "entrypoint" { "null" } else { "[\"/usr/local/bin/syft\"]" }),
        "create" => {
            for flag in ["--pull=never", "--network=none", "--read-only", "--user=65532:65532", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=256m", "--memory-swap=256m", "--cpus=1"] {
                assert!(args.iter().any(|arg| arg == flag));
            }
            assert_eq!(args.len(), 14);
            if mode == "create-cancel" { cancel(&root); }
            if mode.starts_with("create-") { std::process::exit(7); }
            println!("synthetic-container");
        }
        "export" => {
            assert_eq!(args[1], "--output");
            let metadata = std::fs::metadata(&args[2]).unwrap();
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            if mode == "export-cancel" { cancel(&root); }
            eprintln!("synthetic-private-diagnostic");
            std::process::exit(8);
        }
        "rm" => { assert_eq!(args[1], "--force"); if mode == "cleanup-fail" { std::process::exit(9); } }
        _ => panic!("only inspect/create/export/rm are allowed"),
    }
}
fn cancel(root: &std::path::Path) {
    let pid = std::fs::read_to_string(root.join("pid")).unwrap();
    assert!(Command::new("/bin/kill").args(["-INT", "--", pid.trim()]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap().success());
}
"#).unwrap();
        let bin = driver.logs.join("bin");
        fs::create_dir(&bin).unwrap();
        let mut compile = std::process::Command::new("rustc");
        compile
            .args(["--edition=2024", "--crate-name", "filesystem_fake"])
            .arg(&source)
            .arg("-o")
            .arg(bin.join("docker"));
        driver.execute(compile, 60, false, 0).unwrap();
        let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        )))
        .unwrap();
        for mode in [
            "entrypoint",
            "create-fail",
            "export-fail",
            "create-cancel",
            "export-cancel",
            "cleanup-fail",
        ] {
            let root = driver.logs.join(mode);
            fs::create_dir(&root).unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "filesystem::tests::filesystem_check_failure_fixture",
                    "--ignored",
                    "--nocapture",
                ])
                .env("PATH", &path)
                .env("FILESYSTEM_FAKE_ROOT", &root)
                .env("FILESYSTEM_FAKE_MODE", mode);
            driver.execute(child, 30, false, 0).unwrap();
        }
    }

    #[test]
    #[ignore = "approved native local Docker only; builds public inputs, never starts containers"]
    fn native_all_nine_final_filesystems() {
        let mut driver = Driver::new().unwrap();
        for tool in super::super::TOOLS {
            let image = driver.build(tool).unwrap();
            check(&mut driver, tool, &image)
                .unwrap_or_else(|error| panic!("{tool}: {error}; private evidence retained"));
            println!("{tool}: stopped-container filesystem contract passed");
        }
        for entry in fs::read_dir(&driver.logs).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().is_some_and(|s| s == "tar") {
                assert_eq!(
                    entry.metadata().unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }
}
