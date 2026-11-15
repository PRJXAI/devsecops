//! Fixed current Gitleaks Go/legal proposal; no native runtime/source approval.
use super::*;
use sha2::Digest;

#[test]
#[ignore = "two unchanged run43753305153 captures and public checksum-verified sources; collection is not approval"]
fn collect_current_gitleaks_go_notices() -> Result<()> {
    let mut driver = Driver::new()?;
    let output = driver.root.join(".work/gitleaks-go-notice-collection");
    mkdir(&output, false)?;
    let cache = driver.root.join(".work/gitleaks-go-notice-source-cache");
    if !cache.exists() {
        mkdir(&cache, false)?;
    }
    if !cache
        .symlink_metadata()
        .map_err(|_| "missing legal cache")?
        .is_dir()
    {
        return Err("legal cache is not a real directory");
    }
    let mut reference = None;
    for (arch, expected) in [
        (
            "amd64",
            "6ded750d8b861eb42e569fedf8b3335fea280ed00837dff3b5b97c8ced681728",
        ),
        (
            "arm64",
            "b8463ee90a93ac82e34ab893fe339db90863c50483614426fd6885cbe1eb8e6e",
        ),
    ] {
        let path = driver.root.join(format!(
            ".work/gitleaks-current-captures/{arch}/gitleaks.syft.json"
        ));
        if hash(&path, 8 * 1024 * 1024)? != expected {
            return Err("changed Gitleaks legal capture");
        }
        let doc = read_json(&path)?;
        let metadata = &doc["source"]["metadata"];
        if metadata["architecture"] != arch
            || metadata["os"] != "linux"
            || metadata["labels"]["org.opencontainers.image.revision"]
                != "8f3e46e8f4919a106ef0040b5daf1502fc5c20d2"
            || metadata["labels"]["org.opencontainers.image.source"]
                != "https://github.com/PRJXAI/devsecops"
        {
            return Err("foreign Gitleaks legal capture");
        }
        let mut modules = BTreeSet::new();
        let mut main = false;
        for package in doc["artifacts"]
            .as_array()
            .ok_or("missing native legal graph")?
        {
            if package["type"] != "go-module" {
                continue;
            }
            if package["metadata"]["goCompiledVersion"] != "go1.27.4" {
                return Err("foreign Gitleaks compiler");
            }
            let name = text(package, "/name")?;
            if name == "stdlib" {
                continue;
            }
            let version = text(package, "/version")?;
            if name.contains([' ', '\n', '@'])
                || !version.starts_with('v')
                || version.contains([' ', '\n', '@'])
                || version.ends_with("+dirty")
            {
                return Err("unresolved legal module");
            }
            if name == "github.com/zricethezav/gitleaks/v8" {
                if version != "v8.30.1"
                    || package["metadataType"] != "go-module-buildinfo-entry"
                    || package["metadata"]["mainModule"] != name
                {
                    return Err("foreign Gitleaks main module");
                }
                let mut settings = BTreeMap::new();
                for entry in package["metadata"]["goBuildSettings"]
                    .as_array()
                    .ok_or("missing Go build settings")?
                {
                    if settings
                        .insert(text(entry, "/key")?, text(entry, "/value")?)
                        .is_some()
                    {
                        return Err("duplicate Go build setting");
                    }
                }
                if settings.get("CGO_ENABLED") != Some(&"0")
                    || settings.get("GOOS") != Some(&"linux")
                    || settings.get("GOARCH") != Some(&arch)
                    || settings.contains_key("vcs.revision")
                {
                    return Err("archive-built Gitleaks identity differs");
                }
                main = true;
            }
            modules.insert(format!("{name}@{version}"));
        }
        if !main || reference.as_ref().is_some_and(|old| *old != modules) {
            return Err("native Gitleaks module graphs differ");
        }
        reference = Some(modules);
    }
    let modules = reference.ok_or("missing native module graph")?;
    let mut command = Command::new("go");
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("missing Go PATH")?)
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
        .args(
            modules
                .iter()
                .filter(|module| module.as_str() != "github.com/zricethezav/gitleaks/v8@v8.30.1"),
        );
    let downloaded = driver.execute(command, 600, false, 0)?;
    let mut sources = BTreeMap::new();
    for value in serde_json::Deserializer::from_slice(&bytes(&downloaded, 8 * 1024 * 1024)?)
        .into_iter::<Value>()
    {
        let value = value.map_err(|_| "invalid module source response")?;
        if value.get("Error").is_some() || !text(&value, "/Sum")?.starts_with("h1:") {
            return Err("unverified module source");
        }
        let key = format!("{}@{}", text(&value, "/Path")?, text(&value, "/Version")?);
        if sources.insert(key, value).is_some() {
            return Err("duplicate downloaded legal module");
        }
    }
    if sources.len() + 1 != modules.len() {
        return Err("incomplete Gitleaks dependency source graph");
    }
    // The proxy's immutable v8.30.1 origin is 8d1f98c..., while the fixed
    // build source is 83d9cd.... Do not misattribute that source to the proxy
    // tag or rewrite the binary's native version. Collect its exact archive.
    let mut command = Command::new("/usr/bin/curl");
    command.env_clear().env("PATH", "/usr/bin:/bin").args(["--disable", "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--proto-redir", "=https", "--max-time", "120", "--max-filesize", "1048576", "https://codeload.github.com/gitleaks/gitleaks/tar.gz/83d9cd684c87d95d656c1458ef04895a7f1cbd8e"]);
    let main_archive = driver.execute(command, 130, false, 0)?;
    let main_archive_hash = "6b2638a733b85619dc80bdf28e84e4fed7e526a761ab5c148fbf67695aea2115";
    if hash(&main_archive, 1024 * 1024)? != main_archive_hash {
        return Err("foreign Gitleaks main source archive");
    }
    let mut command = Command::new("tar");
    command.arg("-tf").arg(&main_archive);
    let listing = driver.execute(command, 30, false, 0)?;
    let listing = String::from_utf8(bytes(&listing, 1024 * 1024)?)
        .map_err(|_| "invalid main source paths")?;
    let prefix = "gitleaks-83d9cd684c87d95d656c1458ef04895a7f1cbd8e/";
    let mut main_legal = Vec::new();
    for path in listing.lines() {
        let relative = path
            .strip_prefix(prefix)
            .ok_or("escaping main source prefix")?;
        if Path::new(relative)
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err("escaping main source path");
        }
        if path.ends_with('/')
            || !Path::new(relative)
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(legal)
        {
            continue;
        }
        let mut command = Command::new("tar");
        command.arg("-xOf").arg(&main_archive).arg("--").arg(path);
        let file = driver.execute(command, 30, false, 0)?;
        let data = bytes(&file, 1024 * 1024)?;
        if relative == "LICENSE"
            && hash(&file, 1024 * 1024)?
                != "e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6"
        {
            return Err("main source license differs from fixed runtime recipe");
        }
        main_legal.push((relative.to_owned(), data));
    }
    if !main_legal.iter().any(|(path, _)| path == "LICENSE") {
        return Err("missing fixed main license");
    }
    // The exact reviewed compiler material is reused, not recollected from an
    // unrelated source tree or inferred from the scanner's upstream commit.
    let go_source = driver.root.join("licenses/scanners/syft-NOTICES.txt");
    let go_bundle_hash = "06bec637a9fab5fb511f91c22d1cfaf59f76340bc4d9aeb45f01f9468546b3be";
    if hash(&go_source, 8 * 1024 * 1024)? != go_bundle_hash {
        return Err("changed reviewed compiler notices");
    }
    let compiler_material = bytes(&go_source, 8 * 1024 * 1024)?;
    let marker = b"\n--- Go go1.27.4 / ";
    let start = compiler_material
        .windows(marker.len())
        .position(|p| p == marker)
        .ok_or("missing compiler texts")?;
    let go_tail = &compiler_material[start..];
    if go_tail
        .windows(marker.len())
        .filter(|p| *p == marker)
        .count()
        != 38
    {
        return Err("incomplete compiler legal tail");
    }
    let patch = "patches/gitleaks-8.30.1-dependencies.patch.txt";
    let patch_hash = hash(&driver.root.join(patch), 1024 * 1024)?;
    let mut bundle = format!("Modified distribution: Gitleaks 8.30.1-dependency-security.1, rebuilt by PRJXAI.\nUpstream source: https://github.com/gitleaks/gitleaks/tree/83d9cd684c87d95d656c1458ef04895a7f1cbd8e\nChanges: dependency manifests updated for Go 1.27.4, x/crypto 0.59.0 and Brotli 1.3.0 (plus the exact resolved companion modules). Patch: {patch}; SHA-256 {patch_hash}.\nThe Brotli streaming race synchronization change applies only to an upstream TEST copy; production module sources remain checksum-verified and untouched.\nExact source archives, patches, recipe and source checksums are in the org.opencontainers.image.revision tree at https://github.com/PRJXAI/devsecops . Native embedded versions are not rewritten. The embedded v8.30.1 label does not identify the proxy tag's different 8d1f98c7967eb1e79cb44ac6241a124e145d2165 origin; main legal attribution uses the exact 83d9cd source archive above.\nCompiler legal source: Go 1.27.4 commit 7b2881024c95a11ddb86663a616340aa3a88b67f.\nThis bundle covers Go/compiler material only; Git/native runtime notices and corresponding source are separate mandatory arrangements.\nUpstream endorsement is not claimed; original terms are not relicensed. Original texts follow source headings.\n").into_bytes();
    let mut records = Vec::new();
    for module in &modules {
        if module == "github.com/zricethezav/gitleaks/v8@v8.30.1" {
            let mut legal_files = Vec::new();
            for (path, data) in &main_legal {
                append(
                    &mut bundle,
                    &format!(
                        "github.com/zricethezav/gitleaks/v8 / fixed source 83d9cd684c87d95d656c1458ef04895a7f1cbd8e / {path}"
                    ),
                    data,
                )?;
                legal_files.push(json!({"path":path,"sha256":sha2::Sha256::digest(data).iter().map(|b|format!("{b:02x}")).collect::<String>(),"bytes":data.len()}));
            }
            records.push(json!({"module":module,"source_kind":"fixed-upstream-archive; not proxy-tag origin","source_commit":"83d9cd684c87d95d656c1458ef04895a7f1cbd8e","archive_sha256":main_archive_hash,"native_embedded_version":"v8.30.1","observed_proxy_tag_origin":"8d1f98c7967eb1e79cb44ac6241a124e145d2165","files":legal_files}));
            continue;
        }
        let source = &sources[module];
        let directory = PathBuf::from(text(source, "/Dir")?);
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
            return Err("native module has no retrieved legal text");
        }
        let mut legal = Vec::new();
        for path in files {
            let data = bytes(&directory.join(&path), 1024 * 1024)?;
            append(
                &mut bundle,
                &format!("{module} / {}", path.display()),
                &data,
            )?;
            legal.push(json!({"path":path,"sha256":sha2::Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect::<String>(),"bytes":data.len()}));
        }
        records.push(
            json!({"module":module,"sum":source["Sum"],"origin":source["Origin"],"files":legal}),
        );
    }
    if bundle.len() + go_tail.len() > 8 * 1024 * 1024 {
        return Err("Gitleaks legal byte budget");
    }
    bundle.extend_from_slice(go_tail);
    let file = output.join("gitleaks-GO-NOTICES.txt");
    write_new(&file, &bundle, 0o444)?;
    write_json(
        &output.join("gitleaks-index.json"),
        &json!({"tool":"gitleaks","captured_run":43753305153u64,"source_sha":"8f3e46e8f4919a106ef0040b5daf1502fc5c20d2","native_modules":modules,"modules":records,"go_source_commit":"7b2881024c95a11ddb86663a616340aa3a88b67f","go_source_version":"go1.27.4","go_legal_files":38,"reviewed_go_bundle_sha256":go_bundle_hash,"go_legal_tail_sha256":sha2::Sha256::digest(go_tail).iter().map(|b|format!("{b:02x}")).collect::<String>(),"bundle_sha256":hash(&file,8*1024*1024)?,"bundle_bytes":bundle.len(),"redistribution_approved":false}),
    )
}
