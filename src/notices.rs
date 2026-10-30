//! Fixed scanner notice collection. Public source retrieval only; never builds a supplier.
use super::{Driver, Result};
use crate::release::{bytes, hash, mkdir, read_json, text, write_json, write_new};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub(super) fn bundle(root: &Path, tool: &str) -> Result<Vec<u8>> {
    let expected = match tool {
        "syft" => "5d56eacef92c66e40d44034914d53dc599f68542388aa91542e71cef8b88ac15",
        "grype" => "2a1096158a1f761a9366ddd7b99dfb01bd50aa1eea1299d7d8f0e8e4397e86a2",
        "static-base" => "378fef9d3e685a2ad1168283453781a01a66bd8ccc7e261e490340712bf18af4",
        _ => return Err("unsupported scanner notice bundle"),
    };
    let name = if tool == "static-base" {
        "STATIC-BASE"
    } else {
        tool
    };
    let path = root.join(format!("licenses/scanners/{name}-NOTICES.txt"));
    if hash(&path, 8 * 1024 * 1024)? != expected {
        return Err("scanner notice bytes differ from reviewed collection");
    }
    bytes(&path, 8 * 1024 * 1024)
}

const CAPTURES: [(&str, &str, &str); 4] = [
    (
        "syft",
        "amd64",
        "5a5f3414ed8c6756e5f8f54c055ff69280ca292c0e73a1180f3cd09da748fd84",
    ),
    (
        "syft",
        "arm64",
        "fb19c70ec78c583f52930b16c0a8fda80e72f223bc5df59461b508ee7273a669",
    ),
    (
        "grype",
        "amd64",
        "c1acd4f75981463c54cd0f80fdacb8f2d846882e9d2ec5f064198e9f54d618e4",
    ),
    (
        "grype",
        "arm64",
        "544087dc109662e1f5803f2c4c91d643316e22b1e04b4233c5f5a537af793a13",
    ),
];
fn legal(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "license",
        "licence",
        "unlicense",
        "notice",
        "copying",
        "copyright",
    ]
    .iter()
    .any(|p| name.starts_with(p))
        || matches!(name.as_str(), "patents" | "authors")
}
fn texts(root: &Path, path: &Path, result: &mut Vec<PathBuf>, visited: &mut usize) -> Result<()> {
    for item in fs::read_dir(path).map_err(|_| "cannot read module notices")? {
        *visited += 1;
        if *visited > 200_000 {
            return Err("module file budget exceeded");
        }
        let item = item.map_err(|_| "cannot inspect module entry")?;
        let kind = item.file_type().map_err(|_| "cannot inspect module type")?;
        if kind.is_symlink() || (!kind.is_dir() && !kind.is_file()) {
            return Err("nonregular module source entry");
        }
        if kind.is_dir() {
            texts(root, &item.path(), result, visited)?;
        } else if legal(item.file_name().to_str().ok_or("invalid module filename")?) {
            let relative = item
                .path()
                .strip_prefix(root)
                .map_err(|_| "escaping module source")?
                .to_path_buf();
            result.push(relative);
            if result.len() > 2048 {
                return Err("notice file budget exceeded");
            }
        }
    }
    Ok(())
}
fn append(bundle: &mut Vec<u8>, source: &str, data: &[u8]) -> Result<()> {
    let header = format!("\n--- {source} ---\n");
    if data.len() > 1024 * 1024 || bundle.len() + header.len() + data.len() > 8 * 1024 * 1024 {
        return Err("notice bundle byte budget exceeded");
    }
    bundle.extend_from_slice(header.as_bytes());
    bundle.extend_from_slice(data);
    Ok(())
}
fn get(driver: &mut Driver, url: &str) -> Result<PathBuf> {
    if !url.starts_with("https://api.github.com/repos/golang/go/")
        && !url.starts_with("https://raw.githubusercontent.com/golang/go/")
    {
        return Err("unapproved source endpoint");
    }
    if let Some(endpoint) = url.strip_prefix("https://api.github.com/") {
        let mut c = Command::new("gh");
        c.args(["api", endpoint]);
        let output = driver
            .logs
            .join(format!("go-source-{}.json", driver.sequence + 1));
        return driver.execute_to(c, 75, false, 0, Some((&output, 4 * 1024 * 1024)));
    }
    let mut c = Command::new("/usr/bin/curl");
    c.env_clear().env("PATH", "/usr/bin:/bin").args([
        "--disable",
        "--fail",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--connect-timeout",
        "10",
        "--max-time",
        "60",
        "--max-filesize",
        "4194304",
        url,
    ]);
    driver.execute(c, 75, false, 0)
}
pub(super) fn collect(driver: &mut Driver) -> Result<()> {
    let output = driver.root.join(".work/scanner-notice-collection");
    mkdir(&output, false)?;
    let cache = driver.root.join(".work/scanner-notice-source-cache");
    if !cache.exists() {
        mkdir(&cache, false)?;
    }
    if !cache
        .symlink_metadata()
        .map_err(|_| "missing source cache")?
        .is_dir()
    {
        return Err("source cache must be a real directory");
    }
    let mut modules = BTreeSet::new();
    let mut by_tool = BTreeMap::new();
    for tool in ["syft", "grype"] {
        let mut reference = None;
        for (_, arch, expected) in CAPTURES.iter().filter(|(name, _, _)| *name == tool) {
            let path = driver.root.join(format!(
                ".work/delivery-20261030/catalog-{tool}-{arch}/{tool}.syft.json"
            ));
            if hash(&path, 8 * 1024 * 1024)? != *expected {
                return Err("unreviewed scanner catalog");
            }
            let doc = read_json(&path)?;
            if doc["source"]["metadata"]["architecture"] != *arch {
                return Err("scanner catalog architecture mismatch");
            }
            let mut observed = BTreeSet::new();
            for package in doc["artifacts"]
                .as_array()
                .ok_or("missing scanner packages")?
            {
                if package["type"] != "go-module" {
                    continue;
                }
                if package["metadata"]["goCompiledVersion"] != "go1.26.8" {
                    return Err("scanner compiler changed");
                }
                let name = text(package, "/name")?;
                let version = text(package, "/version")?;
                if name == "stdlib" {
                    continue;
                }
                if !version.starts_with('v') || name.contains([' ', '\n', '@']) {
                    return Err("unresolved scanner source module");
                }
                observed.insert(format!("{name}@{version}"));
            }
            if observed.is_empty() || reference.as_ref().is_some_and(|r| *r != observed) {
                return Err("native scanner module graphs differ");
            }
            modules.extend(observed.clone());
            reference = Some(observed);
        }
        by_tool.insert(tool, reference.ok_or("missing native scanner graph")?);
    }
    // Fixed public module proxy, checksum verification on, no VCS/private fallback,
    // operator Go settings, workspace or automatic toolchain execution.
    let mut c = Command::new("go");
    c.env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("missing tool PATH")?)
        .env("HOME", &output)
        .env("GOENV", "off")
        .env("GOWORK", "off")
        .env("GOTOOLCHAIN", "go1.27.3")
        .env("GOPATH", &cache)
        .env("GOMODCACHE", cache.join("pkg/mod"))
        .env("GOPROXY", "https://proxy.golang.org")
        .env("GOSUMDB", "sum.golang.org")
        .env("GOPRIVATE", "")
        .env("GONOSUMDB", "")
        .env("GONOPROXY", "")
        .env("GOINSECURE", "")
        .env("GOVCS", "*:off")
        .current_dir(&output)
        .args(["mod", "download", "-json"])
        .args(&modules);
    let downloaded = driver.execute(c, 600, false, 0)?;
    let mut downloads = BTreeMap::new();
    for value in serde_json::Deserializer::from_slice(&bytes(&downloaded, 8 * 1024 * 1024)?)
        .into_iter::<Value>()
    {
        let value = value.map_err(|_| "invalid module source record")?;
        if value.get("Error").is_some() || !text(&value, "/Sum")?.starts_with("h1:") {
            return Err("unverified module download");
        }
        downloads.insert(
            format!("{}@{}", text(&value, "/Path")?, text(&value, "/Version")?),
            value,
        );
    }
    if downloads.len() != modules.len() {
        return Err("incomplete module source retrieval");
    }
    let commit = read_json(&get(
        driver,
        "https://api.github.com/repos/golang/go/commits/go1.26.8",
    )?)?;
    let commit = text(&commit, "/sha")?.to_owned();
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid Go source commit");
    }
    // Partition the source tree before retrieval; never enlarge the 4 MiB
    // response limit after the retained whole-tree overflow.
    let root_tree = read_json(&get(
        driver,
        &format!("https://api.github.com/repos/golang/go/git/trees/{commit}"),
    )?)?;
    let mut source_files = Vec::new();
    let mut pending = vec![(String::new(), root_tree)];
    while let Some((prefix, tree)) = pending.pop() {
        if tree["truncated"] != false {
            return Err("incomplete Go source tree");
        }
        for original in tree["tree"].as_array().ok_or("missing Go source tree")? {
            let mut file = original.clone();
            let path = format!("{prefix}{}", text(original, "/path")?);
            if file["type"] == "tree" {
                let oid = text(&file, "/sha")?;
                let recursive = if path == "src" { "" } else { "?recursive=1" };
                let subtree = read_json(&get(
                    driver,
                    &format!("https://api.github.com/repos/golang/go/git/trees/{oid}{recursive}"),
                )?)?;
                // Recursive responses already include descendant paths. Mark their
                // trees as visited rather than fetching the same subtree again.
                if subtree["truncated"] != false {
                    return Err("incomplete Go source subtree");
                }
                if recursive.is_empty() {
                    pending.push((format!("{path}/"), subtree));
                } else {
                    for entry in subtree["tree"].as_array().ok_or("missing Go subtree")? {
                        if entry["type"] == "blob" {
                            let mut entry = entry.clone();
                            entry["path"] = json!(format!("{path}/{}", text(&entry, "/path")?));
                            source_files.push(entry);
                        }
                    }
                }
            } else {
                file["path"] = json!(path);
                source_files.push(file);
            }
            if source_files.len() > 100_000 {
                return Err("Go source file budget exceeded");
            }
        }
    }
    let mut go_texts = Vec::new();
    for file in &source_files {
        let path = text(file, "/path")?;
        if file["type"] != "blob"
            || !Path::new(path)
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(legal)
        {
            continue;
        }
        if path.contains("..") || !path.is_ascii() {
            return Err("unsafe Go source path");
        }
        let downloaded = get(
            driver,
            &format!("https://raw.githubusercontent.com/golang/go/{commit}/{path}"),
        )?;
        let mut git = Command::new("git");
        git.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["hash-object", "--no-filters"])
            .arg(&downloaded);
        let oid = driver.execute(git, 30, false, 0)?;
        if String::from_utf8(bytes(&oid, 128)?)
            .map_err(|_| "invalid source object hash")?
            .trim()
            != text(file, "/sha")?
        {
            return Err("Go notice source object mismatch");
        }
        go_texts.push((
            format!("Go go1.26.8 / {path}"),
            bytes(&downloaded, 1024 * 1024)?,
        ));
    }
    if !go_texts.iter().any(|(p, _)| p == "Go go1.26.8 / LICENSE") {
        return Err("missing Go license");
    }
    for (tool, graph) in by_tool {
        let mut bundle =
            format!("Third-party notices for {tool}. Original text follows each source heading.\n")
                .into_bytes();
        let mut records = Vec::new();
        for module in graph {
            let value = &downloads[&module];
            let directory = PathBuf::from(text(value, "/Dir")?);
            if !directory.starts_with(cache.join("pkg/mod"))
                || directory
                    .symlink_metadata()
                    .map_err(|_| "missing module source")?
                    .file_type()
                    .is_symlink()
            {
                return Err("untrusted module source directory");
            }
            let mut files = Vec::new();
            texts(&directory, &directory, &mut files, &mut 0)?;
            files.sort();
            if files.is_empty() {
                return Err("module has no retrieved legal texts");
            }
            let mut legal_files = Vec::new();
            for file in files {
                let data = bytes(&directory.join(&file), 1024 * 1024)?;
                append(
                    &mut bundle,
                    &format!("{module} / {}", file.display()),
                    &data,
                )?;
                legal_files.push(json!({"path":file,"sha256":<sha2::Sha256 as sha2::Digest>::digest(&data).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),"bytes":data.len()}));
            }
            records.push(json!({"module":module,"sum":value["Sum"],"origin":value["Origin"],"files":legal_files}));
        }
        for (path, data) in &go_texts {
            append(&mut bundle, path, data)?;
        }
        let file = output.join(format!("{tool}-NOTICES.txt"));
        write_new(&file, &bundle, 0o444)?;
        write_json(
            &output.join(format!("{tool}-index.json")),
            &json!({"tool":tool,"captured_run":41074964808u64,"source_sha":"aaab990627e8f73fb89c5807193092324e3d004d","go_source_commit":commit,"go_legal_files":go_texts.len(),"modules":records,"bundle_sha256":hash(&file, 8 * 1024 * 1024)?,"bundle_bytes":bundle.len(),"redistribution_approved":false}),
        )?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "fixed captured public static-base source/legal assembly; no network or publication"]
    fn assemble_captured_static_base_notices() {
        let mut driver = Driver::new().unwrap();
        let input = driver.root.join(".work/delivery-20261030");
        let archive = input.join("baselayout-source-cgr-follow.apk");
        assert_eq!(
            hash(&archive, 16 * 1024 * 1024).unwrap(),
            "902fc22a76f11e1a5a0cf9960196c91137fa5ece6d1bafca8126f3ff2b1bbabe"
        );
        assert_eq!(
            hash(&input.join("MPL-2.0.txt"), 1024 * 1024).unwrap(),
            "3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04"
        );
        assert_eq!(
            hash(&input.join("tzdata-LICENSE.txt"), 1024 * 1024).unwrap(),
            "0613408568889f5739e5ae252b722a2659c02002839ad970a63dc5e9174b27cf"
        );
        let mut bundle=b"Static-base data notices and source. Base digest: sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9\nCA bundle 20261020-r0: MPL-2.0 AND MIT. The unmodified PEM bundle at /etc/ssl/certs/ca-certificates.crt is editable certificate source data delivered with this image. MPL rights are not restricted. Additional upstream source: https://gitlab.alpinelinux.org/alpine/ca-certificates/-/tree/2058424fda70ee478bcce872dcf141a0c5499ee0\nTimezone data 2026f: public domain; upstream source https://github.com/eggert/tz/tree/2026f\nWolfi baselayout 20230201-r31: MIT. Complete source package: https://apk.cgr.dev/chainguard/aarch64/wolfi-baselayout-source-20230201-r31.apk (SHA-256 902fc22a76f11e1a5a0cf9960196c91137fa5ece6d1bafca8126f3ff2b1bbabe). Original source/control files follow verbatim; source data is not executed. Copyright notices in these source files remain unchanged.\n".to_vec();
        for name in ["MPL-2.0.txt", "tzdata-LICENSE.txt"] {
            append(
                &mut bundle,
                name,
                &bytes(&input.join(name), 1024 * 1024).unwrap(),
            )
            .unwrap();
        }
        append(&mut bundle,"MIT license terms (copyright notices retained in original source data)",b"Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the Software), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\nTHE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n").unwrap();
        let mut command = Command::new("tar");
        command.args(["-tf"]).arg(&archive);
        let list = driver.execute(command, 30, false, 0).unwrap();
        let list = String::from_utf8(bytes(&list, 1024 * 1024).unwrap()).unwrap();
        let mut count = 0;
        for path in list.lines().filter(|p| {
            !p.ends_with('/')
                && (*p == ".PKGINFO"
                    || *p == ".melange.yaml"
                    || *p == ".source.sha256"
                    || p.starts_with("usr/src/wolfi-baselayout/"))
        }) {
            assert!(!path.contains(".."));
            // Listing includes directories without trailing slashes on this tar;
            // only known source text basenames are selected, never extracted paths.
            if !path.contains("/vendor/etc/")
                && !path.ends_with(".yaml")
                && !path.ends_with(".sha256")
                && path != ".PKGINFO"
            {
                continue;
            }
            if path.ends_with("profile.d") || path.ends_with("secfixes.d") {
                continue;
            }
            let mut command = Command::new("tar");
            command.args(["-xOf"]).arg(&archive).arg(path);
            let output = driver.execute(command, 30, false, 0).unwrap();
            let data = bytes(&output, 1024 * 1024).unwrap();
            if path == ".PKGINFO" {
                let text = std::str::from_utf8(&data).unwrap();
                assert!(text.contains("pkgver = 20230201-r31"));
                assert!(text.contains("commit = ed415005c84750f03c4a9252137813734a224ae7"));
            }
            append(&mut bundle, path, &data).unwrap();
            count += 1;
        }
        assert!(count >= 15);
        write_new(&input.join("STATIC-BASE-NOTICES.txt"), &bundle, 0o444).unwrap();
    }
    #[test]
    #[ignore = "fixed private public-module capture inspection"]
    fn missing_legal_texts_in_captured_sources() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let data = bytes(
            &root.join(".work/check-5219-1793375917270490000/1-stdout.log"),
            8 * 1024 * 1024,
        )
        .unwrap();
        let mut missing = Vec::new();
        for value in serde_json::Deserializer::from_slice(&data).into_iter::<Value>() {
            let value = value.unwrap();
            let folder = PathBuf::from(value["Dir"].as_str().unwrap());
            let mut files = Vec::new();
            texts(&folder, &folder, &mut files, &mut 0).unwrap();
            if files.is_empty() {
                missing.push(json!({"module":value["Path"],"version":value["Version"],"origin":value["Origin"]}));
            }
        }
        write_json(
            &root.join(".work/delivery-20261030/missing-module-notices.json"),
            &json!(missing),
        )
        .unwrap();
        assert!(
            missing.is_empty(),
            "module legal texts are missing; private dossier retained"
        );
    }
    #[test]
    fn legal_names_and_prewrite_limits() {
        for name in [
            "LICENSE",
            "LICENSE-MIT",
            "NOTICE.txt",
            "COPYING.LIB",
            "PATENTS",
            "AUTHORS",
            "LICENCE",
            "UNLICENSE",
        ] {
            assert!(legal(name));
        }
        assert!(!legal("README.md"));
        let mut bundle = vec![0; 8 * 1024 * 1024 - 1];
        let before = bundle.len();
        assert!(append(&mut bundle, "source", b"x").is_err());
        assert_eq!(bundle.len(), before);
    }
}
