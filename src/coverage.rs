//! B5: fail-closed regression coverage of captured native payload/dependency catalogs.
//!
//! `inventory/payloads.json` contains ALL observed named tuples (not count thresholds)
//! from the approved `.work/tasks-catalog-evidence/EVIDENCE.md` investigation. Source
//! config/manifest/report digests and the exact independent supplier Syft pin are
//! attribution, NOT authentication or a replacement for the parent's archive/image
//! binding, bounded JSON validation, finding gates or independent publisher checks.
//! Never insert these tuples into a scanner report: this module only reads evidence.
//!
//! Only linux/arm64 was executed. amd64 is deliberately rejected until native
//! evidence is reviewed. Positive catalog profiles: Syft, Grype, Gitleaks and kind.
//! Each Go executable retains its own compiler/stdlib and every captured dependency;
//! Git/PCRE2/zlib and APK-attributed glibc/loader remain independent requirements.
//! These are scanner-recoverable inventories, not proof of all static components.
//! Rust binaries have no captured payload/crate/compiler/stdlib inventory; Docker
//! CLI lacks a known main version AND its dependencies; Kustomize and Kubectl have
//! UNKNOWN components. None may be repaired from CLI versions, labels or plugins.
//! kind's catalog profile says nothing about functional readiness: its required
//! external provider Docker CLI is absent. B4/readiness must continue blocking it.
//! Functional tests, vulnerabilities, licensing/provenance and parent integration
//! remain separate gates. This module alone does not complete B5/release acceptance.

use serde_json::Value;
use std::{collections::BTreeSet, sync::OnceLock};

use super::Result;

const CAPTURED: &str = include_str!("../inventory/payloads.json");
const MISSING: &str = "SBOM omitted or changed a captured payload/dependency tuple";
// Resource budgets only, never package-count coverage predicates. The parent also
// bounds bytes/JSON structure before passing a Value at both release boundaries.
const MAX_ARTIFACTS: usize = 16_384;
const MAX_LOCATIONS: usize = 64;
const MAX_TUPLES: usize = 32_768;

fn baseline() -> Result<&'static Value> {
    static DATA: OnceLock<Result<Value>> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(CAPTURED).map_err(|_| "invalid captured payload baseline")
    })
    .as_ref()
    .map_err(|e| *e)
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty() && s.len() <= 4096)
        .ok_or("missing or invalid payload coverage field")
}

/// Check the unmodified native Syft document before a clean receipt or any push.
/// Success means captured catalog coverage only; see the module's explicit limits.
/// The parent must independently enforce scanner pin, artifact identity and readiness.
pub(super) fn check(sbom: &Value, tool: &str) -> Result<()> {
    let data = baseline()?;
    let profile = data["tools"]
        .get(tool)
        .ok_or("no captured payload coverage profile for tool")?;
    if sbom.pointer("/descriptor/name").and_then(Value::as_str) != Some("syft")
        || sbom.pointer("/descriptor/version").and_then(Value::as_str) != Some("1.55.0")
        || sbom.pointer("/schema/version").and_then(Value::as_str) != Some("16.1.11")
        || sbom.pointer("/source/type").and_then(Value::as_str) != Some("image")
        || sbom.pointer("/source/metadata/os").and_then(Value::as_str) != Some("linux")
    {
        return Err("payload coverage requires the pinned native Syft image catalog");
    }
    if sbom
        .pointer("/source/metadata/architecture")
        .and_then(Value::as_str)
        != Some("arm64")
    {
        return Err("payload coverage lacks reviewed native architecture evidence");
    }
    let artifacts = sbom
        .get("artifacts")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty() && a.len() <= MAX_ARTIFACTS)
        .ok_or("missing or oversized payload coverage artifacts")?;
    let mut observed = BTreeSet::new();
    let mut unknown = false;
    for package in artifacts {
        let kind = field(package, "type")?;
        let name = field(package, "name")?;
        let version = field(package, "version")?;
        let found_by = field(package, "foundBy")?;
        unknown |= version.trim().eq_ignore_ascii_case("UNKNOWN");
        let locations = package
            .get("locations")
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty() && a.len() <= MAX_LOCATIONS)
            .ok_or("missing or oversized payload coverage locations")?;
        for location in locations {
            // Use the observed path verbatim; basename/accessPath/normalization
            // would let a different executable satisfy the original's inventory.
            let path = field(location, "path")?;
            if !path.starts_with('/') {
                return Err("payload coverage location must be absolute");
            }
            if kind == "go-module" {
                let compiler = profile["compilers"]
                    .get(path)
                    .and_then(Value::as_str)
                    .ok_or("Go payload location has no captured compiler inventory")?;
                if package
                    .pointer("/metadata/goCompiledVersion")
                    .and_then(Value::as_str)
                    != Some(compiler)
                    || package.get("metadataType").and_then(Value::as_str)
                        != Some("go-module-buildinfo-entry")
                {
                    return Err("Go payload compiler inventory differs from native capture");
                }
            }
            observed.insert([kind, name, version, found_by, path]);
            if observed.len() > MAX_TUPLES {
                return Err("payload coverage tuple budget exceeded");
            }
        }
    }
    let required = profile["locations"]
        .as_object()
        .filter(|o| !o.is_empty())
        .ok_or("missing captured payload locations")?;
    for (path, rows) in required {
        for row in rows
            .as_array()
            .filter(|a| !a.is_empty())
            .ok_or("invalid captured payload rows")?
        {
            let row = row
                .as_array()
                .filter(|a| a.len() == 4)
                .ok_or("invalid captured payload tuple")?;
            let mut tuple = [""; 5];
            for (i, value) in row.iter().enumerate() {
                tuple[i] = value
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or("invalid captured payload tuple field")?;
            }
            tuple[4] = path;
            if !observed.contains(&tuple) {
                return Err(MISSING);
            }
        }
    }
    // UNKNOWN rows in the baseline document unresolved observations; they are NOT
    // acceptable versions. Do this after tuple matching so plugin/library omissions
    // remain independently testable even for currently blocked tool profiles.
    if unknown {
        return Err("UNKNOWN payload/dependency versions block catalog coverage");
    }
    match tool {
        "syft" | "grype" | "gitleaks" | "kind" => Ok(()),
        "cargo-audit" | "cargo-deny" => Err("Rust payload/dependency/compiler inventory is absent"),
        "docker" => Err("Docker CLI payload version and embedded dependencies remain unresolved"),
        "kustomize" | "kubectl" => Err("payload/component versions remain unresolved"),
        _ => Err("no reviewed payload coverage acceptance profile"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const POSITIVE: [&str; 4] = ["syft", "grype", "gitleaks", "kind"];
    const INCOMPLETE: [&str; 5] = [
        "cargo-audit",
        "cargo-deny",
        "docker",
        "kustomize",
        "kubectl",
    ];

    // Portable projections of actual captured tuples, not invented release modules
    // or a replacement/native SBOM used for scanning. Fresh full native documents
    // must still pass the same production check at both parent call sites.
    fn captured(tool: &str) -> Value {
        let data = baseline().unwrap();
        let profile = &data["tools"][tool];
        let mut artifacts = Vec::new();
        for (path, rows) in profile["locations"].as_object().unwrap() {
            for row in rows.as_array().unwrap() {
                let mut package = json!({
                    "type": row[0], "name": row[1], "version": row[2],
                    "foundBy": row[3], "locations": [{"path": path}]
                });
                if row[0] == "go-module" {
                    package["metadataType"] = json!("go-module-buildinfo-entry");
                    package["metadata"] = json!({"goCompiledVersion": profile["compilers"][path]});
                }
                artifacts.push(package);
            }
        }
        json!({
            "descriptor": {"name": "syft", "version": "1.55.0"},
            "schema": {"version": "16.1.11"},
            "source": {"type": "image", "metadata": {"architecture": "arm64", "os": "linux"}},
            "artifacts": artifacts
        })
    }

    fn index(sbom: &Value, name: &str, path: &str) -> usize {
        sbom["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .position(|p| p["name"] == name && p["locations"][0]["path"] == path)
            .unwrap()
    }

    #[test]
    #[ignore = "approved public pinned native catalog evidence; no Docker/network access"]
    fn native_captured_documents_keep_their_recorded_hashes_and_known_gaps() {
        use sha2::{Digest, Sha256};
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".work/tasks-catalog-evidence");
        for tool in super::super::TOOLS {
            let path = root.join(tool).join("syft.stdout");
            let original = super::super::release::bytes(&path, 64 * 1024 * 1024).unwrap();
            let hash: String = Sha256::digest(&original)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let evidence = &baseline().unwrap()["tools"][tool]["evidence"];
            assert_eq!(evidence["sha256"], hash);
            let document = super::super::release::read_json(&path).unwrap();
            assert_eq!(
                document["source"]["metadata"]["imageID"],
                evidence["config_digest"]
            );
            assert_eq!(
                check(&document, tool).is_ok(),
                POSITIVE.contains(tool),
                "{tool}"
            );
            assert_eq!(
                super::super::release::bytes(&path, 64 * 1024 * 1024).unwrap(),
                original
            );
        }
    }

    #[test]
    fn actual_captured_arm64_profiles_pass_without_modification() {
        for tool in POSITIVE {
            let sbom = captured(tool);
            let unchanged = sbom.clone();
            assert_eq!(check(&sbom, tool), Ok(()), "{tool}");
            assert_eq!(sbom, unchanged);
            assert_eq!(baseline().unwrap()["tools"][tool]["catalog"], "captured");
        }
    }

    #[test]
    fn every_captured_tuple_is_required_not_only_sentinels() {
        // Exhaustively delete every captured package, including non-cobra Go
        // dependencies, each stdlib, Git libraries and both Docker plugins.
        for tool in POSITIVE.into_iter().chain(INCOMPLETE) {
            let sbom = captured(tool);
            for i in 0..sbom["artifacts"].as_array().unwrap().len() {
                let mut omitted = sbom.clone();
                omitted["artifacts"].as_array_mut().unwrap().remove(i);
                assert_eq!(check(&omitted, tool), Err(MISSING), "{tool} tuple {i}");
            }
        }
    }

    #[test]
    fn omitted_replaced_or_misattributed_main_is_not_coverage() {
        for (tool, name) in [
            ("syft", "github.com/anchore/syft"),
            ("grype", "github.com/anchore/grype"),
            ("gitleaks", "github.com/zricethezav/gitleaks/v8"),
            ("kind", "sigs.k8s.io/kind"),
        ] {
            let sbom = captured(tool);
            let path = format!("/usr/local/bin/{tool}");
            let i = index(&sbom, name, &path);
            for (field, value) in [
                ("name", "unrelated/replacement"),
                ("version", "v0.0.0"),
                ("type", "binary"),
                ("foundBy", "file-cataloger"),
            ] {
                let mut changed = sbom.clone();
                changed["artifacts"][i][field] = json!(value);
                assert!(check(&changed, tool).is_err(), "{tool} {field}");
            }
            let mut changed = sbom.clone();
            changed["artifacts"][i]["locations"][0]["path"] = json!("/other/binary");
            assert!(check(&changed, tool).is_err());
            let mut omitted = sbom;
            omitted["artifacts"].as_array_mut().unwrap().remove(i);
            assert_eq!(check(&omitted, tool), Err(MISSING));
        }
    }

    #[test]
    fn native_git_and_each_library_keep_their_own_tuple() {
        let sbom = captured("gitleaks");
        for (name, path, version) in [
            ("git", "/usr/bin/git", "2.56.0-r3"),
            ("pcre2", "/usr/lib/libpcre2-8.so.0", "10.49-r1"),
            ("zlib", "/usr/lib/libz.so.1", "1.3.2.1_rc20260921-r0"),
            ("glibc-2.44", "/usr/lib/apk/db/installed", "2.44-r9"),
            ("ld-linux-2.44", "/usr/lib/apk/db/installed", "2.44-r9"),
        ] {
            let i = index(&sbom, name, path);
            assert_eq!(sbom["artifacts"][i]["version"], version);
            for (field, value) in [
                ("version", "2.56.0.1.g02cd7dbd28"), // Git CLI != APK version
                ("type", "go-module"),
                ("foundBy", "go-module-binary-cataloger"),
            ] {
                let mut changed = sbom.clone();
                changed["artifacts"][i][field] = json!(value);
                assert!(check(&changed, "gitleaks").is_err(), "{name} {field}");
            }
            let mut changed = sbom.clone();
            changed["artifacts"][i]["locations"][0]["path"] = json!("/usr/bin/git-wrong");
            assert_eq!(check(&changed, "gitleaks"), Err(MISSING));
        }
    }

    #[test]
    fn docker_plugins_do_not_mask_each_other_or_the_cli_gap() {
        let sbom = captured("docker");
        assert!(check(&sbom, "docker").is_err());
        for (name, path) in [
            (
                "github.com/docker/compose/v5",
                "/usr/local/libexec/docker/cli-plugins/docker-compose",
            ),
            (
                "github.com/docker/buildx",
                "/usr/local/libexec/docker/cli-plugins/docker-buildx",
            ),
        ] {
            for dependency in [
                name,
                "stdlib",
                "golang.org/x/crypto",
                "github.com/containerd/console",
            ] {
                let i = index(&sbom, dependency, path);
                let mut omitted = sbom.clone();
                omitted["artifacts"].as_array_mut().unwrap().remove(i);
                assert_eq!(check(&omitted, "docker"), Err(MISSING));
                let mut misplaced = sbom.clone();
                misplaced["artifacts"][i]["locations"][0]["path"] = json!("/usr/local/bin/docker");
                assert_eq!(check(&misplaced, "docker"), Err(MISSING));
            }
        }
        let i = index(
            &sbom,
            "github.com/docker/cli/cmd/docker",
            "/usr/local/bin/docker",
        );
        let mut invented = sbom;
        invented["artifacts"][i]["version"] = json!("v29.9.2");
        assert_eq!(check(&invented, "docker"), Err(MISSING));
    }

    #[test]
    fn compilers_and_stdlib_are_required_per_binary() {
        for tool in POSITIVE {
            let sbom = captured(tool);
            let path = format!("/usr/local/bin/{tool}");
            let i = index(&sbom, "stdlib", &path);
            for replacement in [Value::Null, json!("go0.0.0"), json!("UNKNOWN")] {
                let mut changed = sbom.clone();
                changed["artifacts"][i]["metadata"]["goCompiledVersion"] = replacement;
                assert!(check(&changed, tool).is_err());
            }
            let mut changed = sbom;
            changed["artifacts"][i]["version"] = json!("go0.0.0");
            assert_eq!(check(&changed, tool), Err(MISSING));
        }
    }

    #[test]
    fn all_known_incomplete_tools_remain_blocked_even_with_version_labels() {
        for tool in INCOMPLETE {
            let mut sbom = captured(tool);
            sbom["source"]["metadata"]["labels"] =
                json!({"org.opencontainers.image.version": "1.37.0"});
            assert!(check(&sbom, tool).is_err(), "{tool}");
            assert_eq!(baseline().unwrap()["tools"][tool]["catalog"], "blocked");
            // Do not let a caller replace UNKNOWN from CLI/labels or simply drop it.
            for i in 0..sbom["artifacts"].as_array().unwrap().len() {
                if sbom["artifacts"][i]["version"] == "UNKNOWN" {
                    let mut guessed = sbom.clone();
                    guessed["artifacts"][i]["version"] = json!("v1.37.0");
                    assert_eq!(check(&guessed, tool), Err(MISSING));
                }
            }
        }
    }

    #[test]
    fn base_only_empty_and_unrelated_catalogs_never_pass() {
        for tool in POSITIVE.into_iter().chain(INCOMPLETE) {
            let mut sbom = captured(tool);
            sbom["artifacts"]
                .as_array_mut()
                .unwrap()
                .retain(|p| p["locations"][0]["path"] == "/usr/lib/apk/db/installed");
            assert!(check(&sbom, tool).is_err(), "{tool}");
            sbom["artifacts"] = json!([]);
            assert!(check(&sbom, tool).is_err());
            sbom["artifacts"] = json!([{"type": "apk", "name": "unrelated", "version": "1",
                "foundBy": "apk-db-cataloger", "locations": [{"path": "/unrelated"}]}]);
            assert!(check(&sbom, tool).is_err());
        }
    }

    #[test]
    fn unknown_additional_dependencies_and_malformed_fields_fail_closed() {
        let sbom = captured("kind");
        for version in [
            json!("UNKNOWN"),
            json!("unknown"),
            json!(" UNKNOWN "),
            json!(""),
            Value::Null,
        ] {
            let mut changed = sbom.clone();
            changed["artifacts"].as_array_mut().unwrap().push(json!({
                "type": "apk", "name": "additional-dependency", "version": version,
                "foundBy": "apk-db-cataloger", "locations": [{"path": "/usr/lib/apk/db/installed"}]
            }));
            assert!(check(&changed, "kind").is_err());
        }
        for (field, replacement) in [
            ("foundBy", Value::Null),
            ("type", json!(4)),
            ("name", json!("")),
            ("locations", json!([])),
            ("locations", json!([{"accessPath": "/usr/local/bin/kind"}])),
        ] {
            let mut changed = sbom.clone();
            changed["artifacts"][0][field] = replacement;
            assert!(check(&changed, "kind").is_err());
        }
    }

    #[test]
    fn unverified_architectures_scanners_and_non_native_formats_are_rejected() {
        let sbom = captured("kind");
        for pointer in [
            "/source/metadata/architecture",
            "/source/metadata/os",
            "/source/type",
            "/descriptor/name",
            "/descriptor/version",
            "/schema/version",
        ] {
            for value in [Value::Null, json!("amd64"), json!("unreviewed")] {
                let mut changed = sbom.clone();
                *changed.pointer_mut(pointer).unwrap() = value;
                assert!(check(&changed, "kind").is_err(), "{pointer}");
            }
        }
        assert!(check(&sbom, "unknown-tool").is_err());
    }

    #[test]
    fn evidence_attribution_is_explicit_not_release_approval() {
        let data = baseline().unwrap();
        assert_eq!(
            data["scanner"]["image"],
            "anchore/syft@sha256:ec5bdbc745485920c6f444239f0c09ed87b3c4c165ff9433f95bc66b3500fbf9"
        );
        assert_eq!(data["scanner"]["schema"], "16.1.11");
        assert_eq!(data["platform"], "linux/arm64");
        assert!(
            data["tools"]["kind"]["limitation"]
                .as_str()
                .unwrap()
                .contains("provider Docker CLI absent")
        );
        for tool in POSITIVE.into_iter().chain(INCOMPLETE) {
            let profile = &data["tools"][tool];
            assert_eq!(profile["evidence"]["sha256"].as_str().unwrap().len(), 64);
            for field in ["config_digest", "manifest_digest"] {
                assert!(
                    profile["evidence"][field]
                        .as_str()
                        .unwrap()
                        .starts_with("sha256:")
                );
            }
        }
    }
}
