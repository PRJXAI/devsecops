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
        "syft" => "06bec637a9fab5fb511f91c22d1cfaf59f76340bc4d9aeb45f01f9468546b3be",
        "grype" => "c94fabd9eb510f00c2281efeefdb7b402a6d65952fa46ef7f86c8fff135c2af7",
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

// Four unchanged native captures from run 43730804248, source-bound to the
// actual PR merge tree. Collection proposes texts; it never approves delivery.
const CAPTURES: [(&str, &str, &str); 4] = [
    (
        "syft",
        "amd64",
        "da65d45f9ecb47041cb8f8e0fc68eb8270786113e4df043f9d3dd20c90ebf45c",
    ),
    (
        "syft",
        "arm64",
        "6bea8858bafe08aa45584612775899c56f6985d779dee7e79446fedf48afd4be",
    ),
    (
        "grype",
        "amd64",
        "c168cea4d612a5e4637e026c0591f8d19a6dc337849cfe62afef37f01ae9dde8",
    ),
    (
        "grype",
        "arm64",
        "a3fc72043c332d73043837035e792c3f9bb4b35c23c52d7fd131914b0312daeb",
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
// Legal-source attribution is distinct from the untouched native artifact version.
// The derivative main modules have authentic VCS +dirty versions, not released tags.
// Their unchanged legal texts come from the exact pinned upstream source base;
// dependency-manifest patches and all replacement modules are attributed separately.
fn module_source(package: &Value, tool: &str) -> Result<String> {
    let name = text(package, "/name")?;
    let version = text(package, "/version")?;
    if version.eq_ignore_ascii_case("UNKNOWN") || name.contains([' ', '\n', '@']) {
        return Err("unresolved scanner source module");
    }
    let (main, base, commit) = match tool {
        "syft" => (
            "github.com/anchore/syft",
            "v1.57.1",
            "a0c0d3890a9d79421c403e8fcadec50a2e55bf21",
        ),
        "grype" => (
            "github.com/anchore/grype",
            "v0.121.3",
            "cd1f23eb50dfb52647090158f453c7359172591f",
        ),
        _ => return Err("unsupported fixed scanner source"),
    };
    if name != main {
        if !version.starts_with('v')
            || version.contains([' ', '\n', '@'])
            || version.ends_with("+dirty")
        {
            return Err("unresolved dependency source version");
        }
        return Ok(format!("{name}@{version}"));
    }
    if package["type"] != "go-module"
        || package["metadataType"] != "go-module-buildinfo-entry"
        || package["metadata"]["mainModule"] != main
        || package["metadata"]["goCompiledVersion"] != "go1.27.4"
        || !version.starts_with("v0.0.0-")
        || !version.ends_with(&format!("-{}+dirty", &commit[..12]))
    {
        return Err("main derivative source identity mismatch");
    }
    let mut settings = BTreeMap::new();
    for setting in package["metadata"]["goBuildSettings"]
        .as_array()
        .ok_or("missing native source settings")?
    {
        if settings
            .insert(text(setting, "/key")?, text(setting, "/value")?)
            .is_some()
        {
            return Err("duplicate native source setting");
        }
    }
    for (key, expected) in [
        ("vcs", "git"),
        ("vcs.revision", commit),
        ("vcs.modified", "true"),
        ("CGO_ENABLED", "0"),
        ("GOOS", "linux"),
    ] {
        if settings.get(key).copied() != Some(expected) {
            return Err("main source provenance differs from fixed recipe");
        }
    }
    Ok(format!("{name}@{base}"))
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
    let mut native_versions = BTreeMap::new();
    for tool in ["syft", "grype"] {
        let mut reference = None;
        let mut native_reference = None;
        for (_, arch, expected) in CAPTURES.iter().filter(|(name, _, _)| *name == tool) {
            let path = driver.root.join(format!(
                ".work/security-repair-captures/{tool}-{arch}/{tool}.syft.json"
            ));
            if hash(&path, 8 * 1024 * 1024)? != *expected {
                return Err("unreviewed scanner catalog");
            }
            let doc = read_json(&path)?;
            if doc["source"]["metadata"]["architecture"] != *arch
                || doc["source"]["metadata"]["labels"]["org.opencontainers.image.revision"]
                    != "d3b870dbb18148fcf71d0ea0986a2eed2b484872"
                || doc["source"]["metadata"]["labels"]["org.opencontainers.image.source"]
                    != "https://github.com/PRJXAI/devsecops"
            {
                return Err("scanner catalog source/architecture mismatch");
            }
            let mut observed = BTreeSet::new();
            let mut native_observed = BTreeSet::new();
            for package in doc["artifacts"]
                .as_array()
                .ok_or("missing scanner packages")?
            {
                if package["type"] != "go-module" {
                    continue;
                }
                if package["metadata"]["goCompiledVersion"] != "go1.27.4" {
                    return Err("scanner compiler changed");
                }
                let name = text(package, "/name")?;
                if name == "stdlib" {
                    continue;
                }
                native_observed.insert(format!("{name}@{}", text(package, "/version")?));
                observed.insert(module_source(package, tool)?);
            }
            if observed.is_empty() || reference.as_ref().is_some_and(|r| *r != observed) {
                return Err("native scanner module graphs differ");
            }
            if native_reference
                .as_ref()
                .is_some_and(|previous| previous != &native_observed)
            {
                return Err("native artifact module versions differ between architectures");
            }
            modules.extend(observed.clone());
            reference = Some(observed);
            native_reference = Some(native_observed);
        }
        by_tool.insert(tool, reference.ok_or("missing native scanner graph")?);
        native_versions.insert(
            tool,
            native_reference.ok_or("missing native module versions")?,
        );
    }
    // Fixed public module proxy, checksum verification on, no VCS/private fallback,
    // operator Go settings, workspace or automatic toolchain execution.
    let mut c = Command::new("go");
    c.env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("missing tool PATH")?)
        .env("HOME", &output)
        .env("GOENV", "off")
        .env("GOWORK", "off")
        .env("GOTOOLCHAIN", "go1.27.4")
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
    for (module, commit) in [
        (
            "github.com/anchore/syft@v1.57.1",
            "a0c0d3890a9d79421c403e8fcadec50a2e55bf21",
        ),
        (
            "github.com/anchore/grype@v0.121.3",
            "cd1f23eb50dfb52647090158f453c7359172591f",
        ),
        (
            "github.com/sbomify/ar@v0.0.0-20261110120314-cac91ea00b05",
            "cac91ea00b0538f92fd42fa3ece0b15adc5ef01f",
        ),
    ] {
        let source = downloads
            .get(module)
            .ok_or("missing fixed main/replacement source")?;
        if source["Origin"]["Hash"] != commit {
            return Err("main/replacement legal source does not match pinned commit");
        }
    }
    let commit = read_json(&get(
        driver,
        "https://api.github.com/repos/golang/go/commits/go1.27.4",
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
            format!("Go go1.27.4 / {path}"),
            bytes(&downloaded, 1024 * 1024)?,
        ));
    }
    if !go_texts.iter().any(|(p, _)| p == "Go go1.27.4 / LICENSE") {
        return Err("missing Go license");
    }
    for (tool, graph) in by_tool {
        let (version, commit, patch) = match tool {
            "syft" => (
                "1.57.1",
                "a0c0d3890a9d79421c403e8fcadec50a2e55bf21",
                "patches/syft-1.57.1-security.patch.txt",
            ),
            "grype" => (
                "0.121.3",
                "cd1f23eb50dfb52647090158f453c7359172591f",
                "patches/grype-0.121.3-security.patch.txt",
            ),
            _ => return Err("unsupported derivative notice"),
        };
        let patch_hash = hash(&driver.root.join(patch), 1024 * 1024)?;
        let mut bundle = format!(
            "Modified distribution: {tool} {version}-dependency-security.1, rebuilt by PRJXAI.\n\
             Upstream source: https://github.com/anchore/{tool}/tree/{commit}\n\
             Changes: dependency manifests patched for x/crypto 0.59.0, OpenTelemetry 1.47.0 and the sbomify/ar negative-member-size fix. Compiler: Go 1.27.4.\n\
             Exact build recipe, modified manifests (patch), and source checksums: the org.opencontainers.image.revision source tree at https://github.com/PRJXAI/devsecops .\n\
             Patch: {patch}; SHA-256 {patch_hash}. Upstream endorsement is not claimed; original terms are not relicensed.\n\
             Native embedded versions are preserved in the source-attributed index, not rewritten as release tags.\n\
             Third-party notices for {tool}. Original text follows each source heading.\n"
        ).into_bytes();
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
            &json!({"tool":tool,"captured_run":43730804248u64,"source_sha":"d3b870dbb18148fcf71d0ea0986a2eed2b484872","go_source_commit":commit,"go_legal_files":go_texts.len(),"native_module_versions":native_versions[tool],"modules":records,"bundle_sha256":hash(&file, 8 * 1024 * 1024)?,"bundle_bytes":bundle.len(),"redistribution_approved":false}),
        )?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_legal_source_mapping_requires_real_native_vcs_identity_not_a_guessed_version() {
        let package = json!({"name":"github.com/anchore/syft","version":"v0.0.0-20261109133238-a0c0d3890a9d+dirty","type":"go-module","metadataType":"go-module-buildinfo-entry","metadata":{"mainModule":"github.com/anchore/syft","goCompiledVersion":"go1.27.4","goBuildSettings":[{"key":"vcs","value":"git"},{"key":"vcs.revision","value":"a0c0d3890a9d79421c403e8fcadec50a2e55bf21"},{"key":"vcs.modified","value":"true"},{"key":"CGO_ENABLED","value":"0"},{"key":"GOOS","value":"linux"}]}});
        assert_eq!(
            module_source(&package, "syft").unwrap(),
            "github.com/anchore/syft@v1.57.1"
        );
        for (pointer, value) in [
            ("/version", json!("UNKNOWN")),
            ("/version", json!("v1.57.1")),
            ("/metadata/goCompiledVersion", json!("go1.26.8")),
            ("/metadata/mainModule", json!("foreign")),
            ("/metadata/goBuildSettings/1/value", json!("foreign")),
            ("/metadata/goBuildSettings/2/value", json!("false")),
            ("/metadata/goBuildSettings/3/value", json!("1")),
            ("/metadata/goBuildSettings/4/value", json!("windows")),
        ] {
            let mut changed = package.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(module_source(&changed, "syft").is_err(), "{pointer}");
        }
        assert_eq!(
            package["version"],
            "v0.0.0-20261109133238-a0c0d3890a9d+dirty"
        );
    }
    #[test]
    fn replacement_sources_keep_actual_module_versions_and_never_restore_abandoned_identity() {
        let package =
            json!({"name":"github.com/sbomify/ar","version":"v0.0.0-20261110120314-cac91ea00b05"});
        assert_eq!(
            module_source(&package, "syft").unwrap(),
            "github.com/sbomify/ar@v0.0.0-20261110120314-cac91ea00b05"
        );
        let incompatible =
            json!({"name":"github.com/example/legacy","version":"v2.0.0+incompatible"});
        assert!(module_source(&incompatible, "grype").is_ok());
        assert!(module_source(&package, "unsupported").is_err());
        for version in ["UNKNOWN", "", "v1.0.0+dirty", "v1.0.0 @foreign"] {
            let mut changed = package.clone();
            changed["version"] = json!(version);
            assert!(module_source(&changed, "syft").is_err());
        }
    }

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
