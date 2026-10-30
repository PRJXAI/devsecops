//! Public package access is a separate post-provenance release gate.
use super::{Driver, Result, release};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path, process::Command};

const LIMIT: u64 = 4 * 1024 * 1024;
fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
struct Member {
    arch: String,
    manifest: String,
    config: String,
}
fn targets(status: &Value, tool: &str) -> Result<Vec<Member>> {
    release::tool_identity(tool)?;
    let source = release::text(status, "/source_sha")?;
    if status["schema"] != 1
        || status["tool"] != tool
        || status["repository"] != format!("ghcr.io/prjxai/devsecops/{tool}")
        || !["clean", "accepted-risk"].contains(&release::text(status, "/status")?)
        || source.len() != 40
        || !source
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !digest(release::text(status, "/manifest_digest")?)
    {
        return Err("invalid public release subject");
    }
    let entries = status["manifests"]
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or("two native release identities required")?;
    let mut seen = BTreeSet::new();
    entries
        .iter()
        .map(|value| {
            let arch = release::text(value, "/arch")?;
            let manifest = release::text(value, "/manifest_digest")?;
            let config = release::text(value, "/config_digest")?;
            if !["amd64", "arm64"].contains(&arch)
                || !seen.insert(arch)
                || !digest(manifest)
                || !digest(config)
            {
                return Err("invalid or duplicate native release identity");
            }
            Ok(Member {
                arch: arch.into(),
                manifest: manifest.into(),
                config: config.into(),
            })
        })
        .collect()
}
fn check_index(index: &Value, members: &[Member]) -> Result<()> {
    let entries = index["manifests"]
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or("public index member count mismatch")?;
    let mut seen = BTreeSet::new();
    for value in entries {
        let arch = release::text(value, "/platform/architecture")?;
        if index["schemaVersion"] != 2
            || value["platform"]["os"] != "linux"
            || !seen.insert(arch)
            || !members
                .iter()
                .any(|m| m.arch == arch && value["digest"] == m.manifest)
        {
            return Err("anonymous index identity/platform mismatch");
        }
    }
    Ok(())
}
fn check_native(manifest: &Value, config: &Value, member: &Member, source: &str) -> Result<()> {
    if manifest["schemaVersion"] != 2
        || manifest.get("manifests").is_some()
        || manifest["config"]["digest"] != member.config
        || !manifest["layers"].as_array().is_some_and(|a| {
            !a.is_empty() && a.iter().all(|v| v["digest"].as_str().is_some_and(digest))
        })
        || config["os"] != "linux"
        || config["architecture"] != member.arch
        || config["config"]["Labels"]["org.opencontainers.image.revision"] != source
    {
        return Err("anonymous native configuration/source mismatch");
    }
    Ok(())
}
fn configure(home: &Path) -> Result<()> {
    // Explicit anonymous GHCR entry prevents Docker from auto-discovering a
    // native keychain credential store. Never copy operator auth/helper config.
    // Fixed plugin paths preserve buildx discovery with a private HOME.
    release::write_json(
        &home.join("config.json"),
        &json!({"auths":{"ghcr.io":{}},"cliPluginsExtraDirs":[
            "/usr/libexec/docker/cli-plugins", "/usr/lib/docker/cli-plugins",
            "/usr/local/lib/docker/cli-plugins", "/opt/homebrew/lib/docker/cli-plugins",
            "/Applications/Docker.app/Contents/Resources/cli-plugins"
        ]}),
    )
}
fn command(root: &Path, home: &Path, reference: &str, raw: bool) -> Result<Command> {
    let path = home
        .to_str()
        .filter(|p| !p.contains(['\n', '\r']))
        .ok_or("invalid anonymous configuration path")?;
    let mut c = Command::new("docker");
    c.current_dir(root)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("DOCKER_CONFIG", home)
        .args(["--config", path, "buildx", "imagetools", "inspect"]);
    if raw {
        c.arg("--raw");
    } else {
        c.args(["--format", "{{json .Image}}"]);
    }
    c.arg(reference);
    Ok(c)
}
fn fetch(
    driver: &mut Driver,
    home: &Path,
    reference: &str,
    expected: Option<&str>,
) -> Result<Value> {
    let path = driver
        .execute(
            command(&driver.root, home, reference, expected.is_some())?,
            120,
            false,
            0,
        )
        .map_err(
            |_| "anonymous package access failed; owner must select Public; private logs retained",
        )?;
    let bytes = release::bytes(&path, LIMIT)?;
    let actual = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if let Some(expected) = expected
        && (!digest(expected) || format!("sha256:{actual}") != expected)
    {
        return Err("anonymous registry digest mismatch");
    }
    release::read_json(&path)
}
pub(super) fn verify(driver: &mut Driver, tool: &str) -> Result<()> {
    let tool = release::tool_identity(tool)?;
    let published = driver.root.join(format!(".work/published-{tool}"));
    let status = release::read_json(&published.join("release-status.json"))?;
    let members = targets(&status, tool)?;
    let repository = release::text(&status, "/repository")?;
    let index_digest = release::text(&status, "/manifest_digest")?;
    let source = release::text(&status, "/source_sha")?;
    let home = driver.logs.join("anonymous-registry");
    release::mkdir(&home, false)?;
    configure(&home)?;
    let index = fetch(
        driver,
        &home,
        &format!("{repository}@{index_digest}"),
        Some(index_digest),
    )?;
    check_index(&index, &members)?;
    let mut verified = Vec::new();
    for member in &members {
        let reference = format!("{repository}@{}", member.manifest);
        let manifest = fetch(driver, &home, &reference, Some(&member.manifest))?;
        let config = fetch(driver, &home, &reference, None)?;
        check_native(&manifest, &config, member, source)?;
        verified.push(json!({"platform":format!("linux/{}", member.arch),"manifest_digest":member.manifest,"config_digest":member.config}));
    }
    release::write_json(
        &published.join("public-access.json"),
        &json!({
            "schema":1,"tool":tool,"source_sha":source,"repository":repository,"manifest_digest":index_digest,
            "anonymous_access_verified":true,"native_members":verified,"created":chrono::Utc::now().to_rfc3339(),
            "scope":"anonymous registry metadata/config access; prior provenance and native qualification remain required"
        }),
    )?;
    println!("{tool}: exact index and both native configurations accessible anonymously");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn status() -> Value {
        json!({"schema":1,"tool":"syft","source_sha":"0".repeat(40),"repository":"ghcr.io/prjxai/devsecops/syft","manifest_digest":format!("sha256:{}", "c".repeat(64)),"status":"accepted-risk","manifests":[
            {"arch":"amd64","manifest_digest":format!("sha256:{}", "a".repeat(64)),"config_digest":format!("sha256:{}", "d".repeat(64))},
            {"arch":"arm64","manifest_digest":format!("sha256:{}", "b".repeat(64)),"config_digest":format!("sha256:{}", "e".repeat(64))}]})
    }
    #[test]
    fn public_subjects_reject_foreign_substituted_duplicate_and_partial_metadata() {
        let good = status();
        let members = targets(&good, "syft").unwrap();
        for (path, value) in [
            ("/tool", json!("grype")),
            ("/source_sha", json!("short")),
            ("/repository", json!("ghcr.io/other/syft")),
            ("/status", json!("findings")),
            ("/manifests/1/arch", json!("amd64")),
            ("/manifests/0/config_digest", json!("latest")),
            ("/manifests", json!([])),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(targets(&bad, "syft").is_err());
        }
        let index = json!({"schemaVersion":2,"manifests":members.iter().map(|m|json!({"digest":m.manifest,"platform":{"os":"linux","architecture":m.arch}})).collect::<Vec<_>>()});
        check_index(&index, &members).unwrap();
        for (path, value) in [
            ("/schemaVersion", json!(1)),
            ("/manifests/0/digest", json!(good["manifest_digest"])),
            ("/manifests/1/platform/architecture", json!("amd64")),
            ("/manifests/0/platform/os", json!("windows")),
        ] {
            let mut bad = index.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(check_index(&bad, &members).is_err());
        }
        let manifest = json!({"schemaVersion":2,"config":{"digest":members[0].config},"layers":[{"digest":members[1].manifest}]});
        let config = json!({"os":"linux","architecture":"amd64","config":{"Labels":{"org.opencontainers.image.revision":"0".repeat(40)}}});
        check_native(&manifest, &config, &members[0], &"0".repeat(40)).unwrap();
        let mut bad = manifest.clone();
        bad["config"]["digest"] = json!(members[1].config);
        assert!(check_native(&bad, &config, &members[0], &"0".repeat(40)).is_err());
        for (path, value) in [
            ("/architecture", json!("arm64")),
            ("/os", json!("windows")),
            (
                "/config/Labels/org.opencontainers.image.revision",
                json!("f".repeat(40)),
            ),
        ] {
            let mut bad = config.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(check_native(&manifest, &bad, &members[0], &"0".repeat(40)).is_err());
        }
    }
    #[test]
    #[ignore = "fixed known-public registry metadata positive control; anonymous, no publication or policy approval"]
    fn anonymous_registry_positive_control() -> Result<()> {
        let mut driver = Driver::new()?;
        let home = driver.logs.join("anonymous-control");
        release::mkdir(&home, false)?;
        configure(&home)?;
        let digest = "sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f";
        let index = fetch(
            &mut driver,
            &home,
            &format!("ghcr.io/gitleaks/gitleaks@{digest}"),
            Some(digest),
        )?;
        let native = index["manifests"]
            .as_array()
            .ok_or("missing control members")?
            .iter()
            .find(|v| v["platform"]["os"] == "linux" && v["platform"]["architecture"] == "amd64")
            .ok_or("missing control platform")?;
        let native_digest = release::text(native, "/digest")?;
        let reference = format!("ghcr.io/gitleaks/gitleaks@{native_digest}");
        fetch(&mut driver, &home, &reference, Some(native_digest))?;
        let config = fetch(&mut driver, &home, &reference, None)?;
        if config["os"] != "linux" || config["architecture"] != "amd64" {
            return Err("invalid control configuration");
        }
        Ok(())
    }
    #[test]
    fn private_configuration_has_only_anonymous_auth_and_fixed_system_plugin_paths() -> Result<()> {
        let driver = Driver::new()?;
        configure(&driver.logs)?;
        let config = release::read_json(&driver.logs.join("config.json"))?;
        assert_eq!(
            config.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["auths", "cliPluginsExtraDirs"]
        );
        assert_eq!(config["auths"], json!({"ghcr.io":{}}));
        assert!(
            config["cliPluginsExtraDirs"]
                .as_array()
                .unwrap()
                .iter()
                .all(|v| v.as_str().unwrap().starts_with('/'))
        );
        assert!(configure(&driver.logs).is_err());
        Ok(())
    }
    #[test]
    #[ignore = "explicit fixed published scanner anonymous-access qualification; no credentials, publication or policy approval"]
    fn fixed_scanner_packages_require_public_access() -> Result<()> {
        let mut driver = Driver::new()?;
        let home = driver.logs.join("anonymous-scanners");
        release::mkdir(&home, false)?;
        configure(&home)?;
        let mut failed = false;
        for (tool, digest) in [
            (
                "syft",
                "sha256:7d484d97e289e8ba108ef17a7ecd9dbbbe457398b92f5f3d79219a6445aaaf2c",
            ),
            (
                "grype",
                "sha256:3079a040326484d0b50ac28c7fc2fb25894a22170e81445ab90c400d091378e0",
            ),
        ] {
            let result = fetch(
                &mut driver,
                &home,
                &format!("ghcr.io/prjxai/devsecops/{tool}@{digest}"),
                Some(digest),
            );
            println!(
                "{tool}: anonymous index access {}",
                if result.is_ok() { "passed" } else { "failed" }
            );
            failed |= result.is_err();
        }
        if failed {
            Err("scanner packages are not yet publicly accessible; private captures retained")
        } else {
            Ok(())
        }
    }
    #[test]
    fn anonymous_command_cannot_inherit_credentials_proxy_or_operator_home() {
        let home = Path::new("/synthetic/anonymous");
        let c = command(
            Path::new("/synthetic"),
            home,
            "ghcr.io/public/tool@sha256:test",
            true,
        )
        .unwrap();
        let env = c
            .get_envs()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            env,
            ["PATH", "HOME", "DOCKER_CONFIG"]
                .map(str::to_owned)
                .into_iter()
                .collect()
        );
        let args = c
            .get_args()
            .map(|v| v.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(&args[..2], &["--config", "/synthetic/anonymous"]);
        assert!(
            !args
                .iter()
                .any(|v| v.contains("login") || v.contains("password"))
        );
    }
}
