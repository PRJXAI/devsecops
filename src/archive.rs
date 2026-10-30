//! Selected config identity from the narrow, single-image `docker image save ID` format.
//! This is not the engine's image/index ID or a verification of the OCI descriptor graph.
//! Layer presence and diff-ID shape/count are checked, not compressed-layer contents.

use rustix::fs::{Mode, OFlags, open};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use super::Result;

const ARCHIVE_LIMIT: u64 = 16 * 1024 * 1024 * 1024;
const MEMBER_LIMIT: u64 = 8 * 1024 * 1024 * 1024;
const JSON_LIMIT: u64 = 1024 * 1024;
const ENTRY_LIMIT: usize = 4096;
const LAYER_LIMIT: usize = 1024;
const SOURCE: &str = "https://github.com/PRJXAI/devsecops";

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hash(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn config_name(name: &str) -> Result<&str> {
    let digest = name
        .strip_prefix("blobs/sha256/")
        .or_else(|| name.strip_suffix(".json"))
        .filter(|s| hex(s, 64))
        .ok_or("invalid saved-image config name")?;
    Ok(digest)
}

fn member_name(name: &[u8], directory: bool) -> Result<String> {
    let name = std::str::from_utf8(name).map_err(|_| "invalid saved-image member name")?;
    let name = if directory {
        name.strip_suffix('/').unwrap_or(name)
    } else {
        name
    };
    if name.is_empty()
        || name.len() > 256
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        || name.split('/').any(|s| matches!(s, "" | "." | ".."))
    {
        return Err("unsafe saved-image member name");
    }
    Ok(name.to_owned())
}

// Use our own nofollow open so this module does not depend on release's visibility.
// Private, stable parent directories remain the caller's responsibility; this does
// not defend against concurrent same-UID writes to an already-open regular file.
fn regular(path: &Path) -> Result<File> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "cannot open saved image")?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|_| "cannot inspect saved image")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > ARCHIVE_LIMIT {
        return Err("saved image must be a nonempty bounded regular file");
    }
    Ok(file)
}

fn json(data: &[u8]) -> Result<Value> {
    // The byte bound and serde_json's default recursion limit bound JSON work.
    serde_json::from_slice(data).map_err(|_| "malformed saved-image JSON")
}

fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("missing saved-image field")
}

// Retain only bounded member metadata and manifest JSON. Raw iteration prevents
// tar from allocating PAX/GNU extensions or interpreting sparse/alternate paths.
// No extraction, archive-sized buffer, or reopen of the selected config occurs.
pub(super) fn saved_config(path: &Path) -> Result<(String, Vec<u8>, usize)> {
    let mut input = regular(path)?.take(ARCHIVE_LIMIT + 1);
    let mut members = BTreeMap::new();
    let mut manifest = None;
    let mut end = 0;
    {
        let mut archive = tar::Archive::new(&mut input);
        let entries = archive
            .entries()
            .map_err(|_| "cannot read saved-image headers")?;
        for (count, entry) in entries.raw(true).enumerate() {
            if count >= ENTRY_LIMIT {
                return Err("saved-image header budget exceeded");
            }
            let mut entry = entry.map_err(|_| "invalid saved-image tar")?;
            let kind = entry.header().entry_type();
            if (!kind.is_file() && !kind.is_dir()) || entry.header().link_name_bytes().is_some() {
                return Err("unsupported saved-image member type");
            }
            let name = member_name(&entry.path_bytes(), kind.is_dir())?;
            let size = entry.size();
            if size > MEMBER_LIMIT || (kind.is_dir() && size != 0) {
                return Err("saved-image member size exceeded");
            }
            let offset = entry.raw_file_position();
            end = offset
                .checked_add(size.div_ceil(512) * 512)
                .filter(|end| *end <= ARCHIVE_LIMIT - 1024)
                .ok_or("saved-image size exceeded")?;
            if members
                .insert(name.clone(), (offset, size, kind.is_file()))
                .is_some()
            {
                return Err("duplicate saved-image member");
            }
            if name == "manifest.json" {
                if !kind.is_file() || size == 0 || size > JSON_LIMIT {
                    return Err("invalid saved-image manifest size or type");
                }
                let mut data = Vec::new();
                entry
                    .read_to_end(&mut data)
                    .map_err(|_| "cannot read saved-image manifest")?;
                if data.len() as u64 != size {
                    return Err("truncated saved-image manifest");
                }
                manifest = Some(data);
            }
        }
    }
    // tar stops at the first zero header (or EOF). Require both end blocks,
    // complete 512-byte framing, and only zero padding afterwards. This rejects
    // truncated archives and appended/concatenated alternative manifests.
    let mut consumed = ARCHIVE_LIMIT + 1 - input.limit();
    if consumed != end + 512 {
        return Err("missing saved-image end marker");
    }
    let mut buffer = [0; 32 * 1024];
    loop {
        let n = input
            .read(&mut buffer)
            .map_err(|_| "cannot read saved-image trailer")?;
        if n == 0 {
            break;
        }
        consumed += n as u64;
        if consumed > ARCHIVE_LIMIT || buffer[..n].iter().any(|b| *b != 0) {
            return Err("invalid saved-image trailer");
        }
    }
    if consumed < end + 1024 || !consumed.is_multiple_of(512) {
        return Err("truncated saved-image trailer");
    }

    let manifest = json(&manifest.ok_or("missing saved-image manifest")?)?;
    let selected = manifest
        .as_array()
        .filter(|entries| entries.len() == 1)
        .and_then(|entries| entries.first())
        .filter(|entry| entry.is_object())
        .ok_or("expected one saved native image")?;
    if !matches!(selected.get("RepoTags"), None | Some(Value::Null))
        && !selected
            .get("RepoTags")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return Err("expected an ID-only saved image");
    }
    let name = text(selected, "/Config")?;
    let expected = config_name(name)?;
    let &(offset, size, file) = members.get(name).ok_or("missing selected config")?;
    if !file || size == 0 || size > JSON_LIMIT {
        return Err("invalid selected config size or type");
    }
    let layers = selected
        .get("Layers")
        .and_then(Value::as_array)
        .filter(|layers| !layers.is_empty() && layers.len() <= LAYER_LIMIT)
        .ok_or("invalid saved-image layers")?;
    for layer in layers {
        let layer = layer.as_str().ok_or("invalid saved-image layer name")?;
        member_name(layer.as_bytes(), false)?;
        if layer == name
            || layer == "manifest.json"
            || !members
                .get(layer)
                .is_some_and(|(_, size, file)| *file && *size != 0)
        {
            return Err("missing or substituted saved-image layer");
        }
    }
    let mut file = input.into_inner();
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| "cannot locate selected config")?;
    let mut data = Vec::new();
    file.take(size)
        .read_to_end(&mut data)
        .map_err(|_| "cannot read selected config")?;
    if data.len() as u64 != size || hash(&data) != expected {
        return Err("selected config digest mismatch");
    }
    Ok((format!("sha256:{expected}"), data, layers.len()))
}

/// Discover the selected config digest, independently of the engine image ID.
pub(super) fn config_digest(path: &Path, arch: &str, revision: &str) -> Result<String> {
    // Release callers validate their source SHA separately; compare this label
    // exactly, including for approved local/public evidence labeled `local`.
    if !matches!(arch, "amd64" | "arm64") || revision.is_empty() || revision.len() > 256 {
        return Err("invalid expected saved-image platform or revision");
    }
    let (digest, data, layer_count) = saved_config(path)?;
    let config = json(&data)?;
    if text(&config, "/os")? != "linux"
        || text(&config, "/architecture")? != arch
        || text(&config, "/config/User")? != "65532:65532"
        || text(&config, "/config/Labels/org.opencontainers.image.source")? != SOURCE
        || text(&config, "/config/Labels/org.opencontainers.image.revision")? != revision
        || text(&config, "/rootfs/type")? != "layers"
    {
        return Err("saved-image config identity mismatch");
    }
    let diff_ids = config
        .pointer("/rootfs/diff_ids")
        .and_then(Value::as_array)
        .filter(|ids| ids.len() == layer_count)
        .ok_or("saved-image diff-ID count mismatch")?;
    if !diff_ids.iter().all(|id| {
        id.as_str()
            .and_then(|id| id.strip_prefix("sha256:"))
            .is_some_and(|id| hex(id, 64))
    }) {
        return Err("invalid saved-image diff ID");
    }
    Ok(digest)
}

/// Synthetic receipt-test input only: an empty layer, not a runnable tool image.
#[cfg(test)]
pub(super) fn fixture(path: &Path, arch: &str, revision: &str) -> String {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
    let layer = {
        let mut builder = tar::Builder::new(Vec::new());
        builder.finish().unwrap();
        builder.into_inner().unwrap()
    };
    let config = serde_json::json!({
        "os": "linux", "architecture": arch,
        "config": {"User": "65532:65532", "Labels": {
            "org.opencontainers.image.source": SOURCE,
            "org.opencontainers.image.revision": revision
        }},
        "rootfs": {"type": "layers", "diff_ids": [format!("sha256:{}", hash(&layer))]}
    });
    let data = serde_json::to_vec(&config).unwrap();
    let digest = hash(&data);
    let name = format!("{digest}.json");
    let manifest = serde_json::to_vec(&serde_json::json!([{
        "Config": name, "RepoTags": null, "Layers": ["layer/layer.tar"]
    }]))
    .unwrap();
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    let mut builder = tar::Builder::new(file);
    for (name, data) in [
        (name.as_str(), data.as_slice()),
        ("layer/layer.tar", layer.as_slice()),
        ("manifest.json", manifest.as_slice()),
    ] {
        let mut header = tar::Header::new_ustar();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, data).unwrap();
    }
    builder.finish().unwrap();
    format!("sha256:{digest}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{DirBuilderExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const REVISION: &str = "1234567890abcdef1234567890abcdef12345678";
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "devsecops-archive-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> PathBuf {
            self.0.join("image.tar")
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn config() -> Value {
        json!({
            "os": "linux", "architecture": "arm64",
            "config": {"User": "65532:65532", "Labels": {
                "org.opencontainers.image.source": SOURCE,
                "org.opencontainers.image.revision": REVISION
            }},
            "rootfs": {"type": "layers", "diff_ids": [format!("sha256:{}", "a".repeat(64))]}
        })
    }

    fn manifest(name: &str) -> Value {
        json!([{"Config": name, "RepoTags": null, "Layers": ["layer/layer.tar"]}])
    }

    fn members(config: &Value, blob: bool) -> Vec<(String, Vec<u8>)> {
        let data = serde_json::to_vec(config).unwrap();
        let name = if blob {
            format!("blobs/sha256/{}", hash(&data))
        } else {
            format!("{}.json", hash(&data))
        };
        vec![
            (name.clone(), data),
            ("layer/layer.tar".into(), vec![0; 1024]),
            (
                "manifest.json".into(),
                serde_json::to_vec(&manifest(&name)).unwrap(),
            ),
        ]
    }

    fn write_members(path: &Path, members: &[(String, Vec<u8>)]) {
        let mut builder = tar::Builder::new(File::create(path).unwrap());
        for (name, data) in members {
            let mut header = tar::Header::new_ustar();
            header.set_path(name).unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, data.as_slice()).unwrap();
        }
        builder.finish().unwrap();
    }

    fn rejected(members: &[(String, Vec<u8>)]) {
        let root = Root::new();
        write_members(&root.path(), members);
        assert!(config_digest(&root.path(), "arm64", REVISION).is_err());
    }

    #[test]
    fn synthetic_classic_and_blob_configs_and_receipt_fixture() {
        let root = Root::new();
        for blob in [false, true] {
            let members = members(&config(), blob);
            write_members(&root.path(), &members);
            let expected = format!("sha256:{}", hash(&members[0].1));
            assert_eq!(config_digest(&root.path(), "arm64", REVISION), Ok(expected));
        }
        fs::remove_file(root.path()).unwrap();
        let expected = fixture(&root.path(), "amd64", REVISION);
        assert_eq!(config_digest(&root.path(), "amd64", REVISION), Ok(expected));
        assert!(config_digest(&root.path(), "arm64", REVISION).is_err());
        assert!(config_digest(&root.path(), "amd64", &"b".repeat(40)).is_err());
        assert!(config_digest(&root.path(), "amd64", "").is_err());
    }

    #[test]
    fn config_identity_and_diff_ids_are_required_not_inferred() {
        for (pointer, replacement) in [
            ("/os", json!("windows")),
            ("/architecture", json!("amd64")),
            ("/config/User", json!("65532")),
            ("/config/User", json!("0:0")),
            (
                "/config/Labels/org.opencontainers.image.source",
                json!("https://example.invalid"),
            ),
            (
                "/config/Labels/org.opencontainers.image.revision",
                json!("b".repeat(40)),
            ),
            ("/rootfs/type", json!("other")),
            ("/rootfs/diff_ids", json!([])),
            ("/rootfs/diff_ids", json!(["sha256:bad"])),
            (
                "/rootfs/diff_ids",
                json!([format!("sha256:{}", "A".repeat(64))]),
            ),
            (
                "/rootfs/diff_ids",
                json!([
                    format!("sha256:{}", "a".repeat(64)),
                    format!("sha256:{}", "b".repeat(64))
                ]),
            ),
            ("/rootfs/diff_ids", Value::Null),
        ] {
            let mut value = config();
            *value.pointer_mut(pointer).unwrap() = replacement;
            rejected(&members(&value, false));
            *value.pointer_mut(pointer).unwrap() = Value::Null;
            rejected(&members(&value, false));
        }
    }

    #[test]
    fn reject_selected_member_duplicates_substitution_and_invalid_manifests() {
        let original = members(&config(), true);
        for index in 0..original.len() {
            let mut changed = original.clone();
            changed.push(original[index].clone());
            rejected(&changed);
            changed.remove(index);
            changed.remove(changed.len() - 1);
            rejected(&changed);
        }
        let mut changed = original.clone();
        changed[0].1.push(b' '); // Valid JSON, but no longer the named config.
        rejected(&changed);
        for value in [
            json!([]),
            json!({}),
            json!([{}, {}]),
            json!([{}]),
            json!([null]),
        ] {
            let mut changed = original.clone();
            changed[2].1 = serde_json::to_vec(&value).unwrap();
            rejected(&changed);
        }
        for data in [
            Vec::new(),
            b"[".to_vec(),
            vec![b' '; JSON_LIMIT as usize + 1],
        ] {
            let mut changed = original.clone();
            changed[2].1 = data;
            rejected(&changed);
        }
        for name in [
            "config.json".into(),
            format!("{}.json", "A".repeat(64)),
            "../config.json".into(),
            format!("other/{}.json", "a".repeat(64)),
        ] {
            let mut changed = original.clone();
            changed[2].1 = serde_json::to_vec(&manifest(&name)).unwrap();
            rejected(&changed);
        }
        for layers in [
            json!([]),
            json!(["missing/layer.tar"]),
            json!([original[0].0]),
            json!(["../layer.tar"]),
            json!([null]),
        ] {
            let mut changed = original.clone();
            let mut value = manifest(&original[0].0);
            value[0]["Layers"] = layers;
            changed[2].1 = serde_json::to_vec(&value).unwrap();
            rejected(&changed);
        }
        let mut changed = original.clone();
        let mut value = manifest(&original[0].0);
        value[0]["RepoTags"] = json!(["mutable:tag"]);
        changed[2].1 = serde_json::to_vec(&value).unwrap();
        rejected(&changed);
        for data in [
            Vec::new(),
            b"{".to_vec(),
            vec![b' '; JSON_LIMIT as usize + 1],
        ] {
            let mut changed = original.clone();
            changed[0].0 = format!("blobs/sha256/{}", hash(&data));
            changed[0].1 = data;
            changed[2].1 = serde_json::to_vec(&manifest(&changed[0].0)).unwrap();
            rejected(&changed);
        }
    }

    #[test]
    fn reject_unsafe_types_names_headers_and_member_budgets() {
        let root = Root::new();
        let original = members(&config(), true);
        write_members(&root.path(), &original);
        let bytes = fs::read(root.path()).unwrap();
        for kind in *b"12346SLKxg" {
            let mut bad = bytes.clone();
            bad[156] = kind;
            let header = tar::Header::from_byte_slice(&bad[..512]);
            let mut header = header.clone();
            header.set_cksum();
            bad[..512].copy_from_slice(header.as_bytes());
            fs::write(root.path(), bad).unwrap();
            assert!(config_digest(&root.path(), "arm64", REVISION).is_err());
        }
        for name in [
            "../config",
            "/absolute",
            "a/../config",
            "a//config",
            "./config",
            "a\\config",
        ] {
            let mut bad = bytes.clone();
            let mut header = tar::Header::from_byte_slice(&bad[..512]).clone();
            header.as_old_mut().name.fill(0);
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            bad[..512].copy_from_slice(header.as_bytes());
            fs::write(root.path(), bad).unwrap();
            assert!(config_digest(&root.path(), "arm64", REVISION).is_err());
        }
        let mut header = tar::Header::new_ustar();
        header.set_path("oversized").unwrap();
        header.set_size(MEMBER_LIMIT + 1);
        header.set_cksum();
        fs::write(root.path(), header.as_bytes()).unwrap();
        assert!(config_digest(&root.path(), "arm64", REVISION).is_err());
        let mut many = original;
        for n in 0..ENTRY_LIMIT {
            many.push((format!("extra-{n}"), Vec::new()));
        }
        rejected(&many);
        let mut bad = bytes;
        bad[148] ^= 1;
        fs::write(root.path(), bad).unwrap();
        assert!(config_digest(&root.path(), "arm64", REVISION).is_err());
    }

    #[test]
    fn reject_nonregular_archives_truncation_and_hidden_trailing_members() {
        let root = Root::new();
        write_members(&root.path(), &members(&config(), false));
        let bytes = fs::read(root.path()).unwrap();
        for length in [
            100,
            512,
            bytes.len() - 1,
            bytes.len() - 512,
            bytes.len() - 1024,
        ] {
            fs::write(root.path(), &bytes[..length]).unwrap();
            assert!(config_digest(&root.path(), "arm64", REVISION).is_err());
        }
        fs::write(root.path(), &bytes).unwrap();
        OpenOptions::new()
            .append(true)
            .open(root.path())
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        assert!(config_digest(&root.path(), "arm64", REVISION).is_err());
        let target = root.0.join("target.tar");
        fs::write(&target, &bytes).unwrap();
        fs::remove_file(root.path()).unwrap();
        symlink(&target, root.path()).unwrap();
        assert!(config_digest(&root.path(), "arm64", REVISION).is_err());
        assert!(config_digest(&root.0, "arm64", REVISION).is_err());
        fs::remove_file(root.path()).unwrap();
        #[cfg(target_os = "linux")]
        {
            rustix::fs::mkfifoat(rustix::fs::CWD, root.path(), Mode::RUSR | Mode::WUSR).unwrap();
            assert!(config_digest(&root.path(), "arm64", REVISION).is_err());
        }
    }

    // Explicit opt-in: approved public evidence only, no Docker or other access.
    #[test]
    #[ignore = "requires approved public saved archives under .work/scans"]
    fn approved_native_scan_archives() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".work/scans");
        check_public(&base, false);
    }

    #[test]
    #[ignore = "requires approved public catalog evidence"]
    fn approved_native_catalog_archives_match_unmodified_syft() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(".work/tasks-catalog-evidence");
        check_public(&base, true);
    }

    fn check_public(base: &Path, catalog: bool) {
        let mut checked = 0;
        for tool in [
            "syft",
            "grype",
            "gitleaks",
            "cargo-audit",
            "cargo-deny",
            "kind",
            "kustomize",
            "kubectl",
            "docker",
        ] {
            let directory = base.join(tool);
            let path = directory.join(if catalog {
                "save.stdout".into()
            } else {
                format!("{tool}-arm64.tar")
            });
            if !path.exists() {
                continue;
            }
            let (expected, data, _) = saved_config(&path).unwrap();
            let config = json(&data).unwrap();
            // Read the actual public config label, never infer a source revision.
            let revision =
                text(&config, "/config/Labels/org.opencontainers.image.revision").unwrap();
            assert_eq!(
                config_digest(&path, "arm64", revision),
                Ok(expected.clone())
            );
            if catalog {
                let report = json(&fs::read(directory.join("syft.stdout")).unwrap()).unwrap();
                assert_eq!(text(&report, "/source/metadata/imageID").unwrap(), expected);
                let inspect = json(&fs::read(directory.join("inspect.stdout")).unwrap()).unwrap();
                assert_ne!(text(&inspect[0], "/Id").unwrap(), expected);
            }
            checked += 1;
        }
        assert!(checked > 0, "no approved public archives found");
        eprintln!("approved saved native archives verified: {checked}");
    }
}
