//! B5: fail-closed regression coverage of captured native payload/dependency catalogs.
//!
//! `inventory/payloads.json` contains ALL observed named tuples (not count thresholds)
//! from the approved `.work/tasks-catalog-evidence/EVIDENCE.md` investigation. Source
//! config/manifest/report digests and the exact independent supplier Syft pin are
//! attribution, NOT authentication or a replacement for the parent's archive/image
//! binding, bounded JSON validation, finding gates or independent publisher checks.
//! Never insert these tuples into a scanner report: this module only reads evidence.
//!
//! Hosted native linux/amd64 and linux/arm64 evidence from run 40571222293 is
//! reviewed in `inventory/native-evidence.json` and `docs/tool-inventory.md`.
//! Only Syft, Grype and Gitleaks have positive profiles on both architectures.
//! Production Gitleaks now requires inventory/gitleaks-production.json, derived
//! from unchanged upgraded native captures; the original supplier profile is
//! historical evidence only, never a production fallback. Others fail closed.
//! Each Go executable retains its own compiler/stdlib and every captured dependency;
//! Git/PCRE2/zlib and APK-attributed glibc/loader remain independent requirements.
//! These are scanner-recoverable inventories, not proof of all static components.
//! Rust binaries have no captured payload/crate/compiler/stdlib inventory; Docker
//! CLI lacks a known main version AND its dependencies; Kustomize and Kubectl have
//! UNKNOWN components. None may be repaired from CLI versions, labels or plugins.
//! kind's recorded catalog predates its added Docker provider CLI. That new payload
//! has no reviewed profile yet, so kind remains blocked even if its old tuples match.
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

fn profile(tool: &str) -> Result<&'static Value> {
    if matches!(tool, "syft" | "grype") {
        static SCANNERS: OnceLock<Result<Value>> = OnceLock::new();
        let data = SCANNERS
            .get_or_init(|| {
                serde_json::from_str(include_str!("../inventory/scanner-production.json"))
                    .map_err(|_| "invalid scanner production inventory profile")
            })
            .as_ref()
            .map_err(|e| *e)?;
        data["tools"]
            .get(tool)
            .ok_or("missing scanner production profile")
    } else if tool == "gitleaks" {
        static PRODUCTION: OnceLock<Result<Value>> = OnceLock::new();
        PRODUCTION
            .get_or_init(|| {
                serde_json::from_str(include_str!("../inventory/gitleaks-production.json"))
                    .map_err(|_| "invalid Gitleaks production inventory profile")
            })
            .as_ref()
            .map_err(|e| *e)
    } else {
        baseline()?["tools"]
            .get(tool)
            .ok_or("no captured payload coverage profile for tool")
    }
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
    let profile = profile(tool)?;
    if sbom.pointer("/descriptor/name").and_then(Value::as_str) != Some("syft")
        || sbom.pointer("/descriptor/version").and_then(Value::as_str) != Some("1.55.0")
        || sbom.pointer("/schema/version").and_then(Value::as_str) != Some("16.1.11")
        || sbom.pointer("/source/type").and_then(Value::as_str) != Some("image")
        || sbom.pointer("/source/metadata/os").and_then(Value::as_str) != Some("linux")
    {
        return Err("payload coverage requires the pinned native Syft image catalog");
    }
    match sbom
        .pointer("/source/metadata/architecture")
        .and_then(Value::as_str)
    {
        Some("arm64") => (), // Retain all historical profiles and their blockers.
        Some("amd64") if ["syft", "grype", "gitleaks"].contains(&tool) => (),
        _ => return Err("payload coverage lacks reviewed native architecture evidence"),
    }
    check_profile(sbom, tool, profile)
}

fn check_profile(sbom: &Value, tool: &str, profile: &Value) -> Result<()> {
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
        "syft" | "grype" | "gitleaks" => Ok(()),
        "kind" => Err("kind Docker provider payload inventory has not been reviewed"),
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

    // Immutable old captures include retired kind, never the replacement k3d.
    const HISTORICAL: &[&str] = &[
        "syft",
        "grype",
        "gitleaks",
        "cargo-audit",
        "cargo-deny",
        "kind",
        "kustomize",
        "kubectl",
        "docker",
    ];
    const POSITIVE: [&str; 3] = ["syft", "grype", "gitleaks"];

    #[test]
    fn replacement_k3d_cannot_borrow_historical_kind_coverage() {
        assert!(super::super::TOOLS.contains(&"k3d"));
        assert!(!super::super::TOOLS.contains(&"kind"));
        assert_eq!(
            check(&captured("kind"), "k3d"),
            Err("no captured payload coverage profile for tool")
        );
    }
    const INCOMPLETE: [&str; 6] = [
        "kind",
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
        let profile = profile(tool).unwrap();
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
        for tool in HISTORICAL {
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
                check_profile(&document, tool, &baseline().unwrap()["tools"][tool]).is_ok(),
                POSITIVE.contains(tool),
                "{tool}"
            );
            assert_eq!(
                super::super::release::bytes(&path, 64 * 1024 * 1024).unwrap(),
                original
            );
        }
    }

    // One approved hosted run, not an extensible artifact authority. Fixed summary
    // and report hashes bind these opt-in tests, never substitute for fresh coverage.
    const HOSTED: &str = include_str!("../inventory/native-evidence.json");
    const HOSTED_REV: &str = "9500de1196b51e2a27143b8188fe08908d4b1f13";
    const HOSTED_SYFT: &str = "anchore/syft:v1.55.0-nonroot@sha256:ec5bdbc745485920c6f444239f0c09ed87b3c4c165ff9433f95bc66b3500fbf9";

    fn sha256(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    // Syft stores the original image config/manifest as standard padded base64.
    // Decode only these small public test inputs; no archive extraction or deps.
    fn embedded_json(document: &Value, field: &str) -> (Vec<u8>, Value) {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let encoded = document["source"]["metadata"][field].as_str().unwrap();
        assert!(!encoded.is_empty() && encoded.len() <= 64 * 1024);
        assert_eq!(encoded.len() % 4, 0);
        let mut bytes = Vec::new();
        for chunk in encoded.as_bytes().as_chunks::<4>().0 {
            let mut value = 0u32;
            for byte in chunk {
                value = (value << 6)
                    | if *byte == b'=' {
                        0
                    } else {
                        ALPHABET.iter().position(|b| b == byte).unwrap() as u32
                    };
            }
            bytes.push((value >> 16) as u8);
            if chunk[2] != b'=' {
                bytes.push((value >> 8) as u8);
            }
            if chunk[3] != b'=' {
                bytes.push(value as u8);
            }
        }
        let json = serde_json::from_slice(&bytes).unwrap();
        (bytes, json)
    }

    fn observations(document: &Value, tool: &str) -> Value {
        let profile = &baseline().unwrap()["tools"][tool];
        let mut observed = BTreeSet::new();
        let mut compilers = BTreeSet::new();
        let mut unknown = BTreeSet::new();
        let mut compiler_gaps = BTreeSet::new();
        for package in document["artifacts"].as_array().unwrap() {
            for location in package["locations"].as_array().unwrap() {
                let row: Vec<String> = ["type", "name", "version", "foundBy"]
                    .into_iter()
                    .map(|key| field(package, key).unwrap().to_owned())
                    .chain(std::iter::once(field(location, "path").unwrap().to_owned()))
                    .collect();
                if row[2].trim().eq_ignore_ascii_case("UNKNOWN") {
                    unknown.insert(row.clone());
                }
                if row[0] == "go-module" {
                    assert_eq!(package["metadataType"], "go-module-buildinfo-entry");
                    let compiler = field(&package["metadata"], "goCompiledVersion").unwrap();
                    compilers.insert([row[4].clone(), compiler.to_owned()]);
                    if profile["compilers"][&row[4]].as_str() != Some(compiler) {
                        compiler_gaps.insert([row[4].clone(), compiler.to_owned()]);
                    }
                }
                observed.insert(row);
            }
        }
        let required: BTreeSet<Vec<String>> = profile["locations"]
            .as_object()
            .unwrap()
            .iter()
            .flat_map(|(path, rows)| {
                rows.as_array().unwrap().iter().map(move |row| {
                    row.as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .chain(std::iter::once(path.clone()))
                        .collect()
                })
            })
            .collect();
        json!({
            "observed_tuples": observed.len(), "required_tuples": required.len(),
            "missing": required.difference(&observed).collect::<Vec<_>>(),
            "additional": observed.difference(&required).collect::<Vec<_>>(),
            "compilers": compilers, "compiler_gaps": compiler_gaps, "unknown": unknown,
            "profile_result": check_profile(document, tool, profile).err()
        })
    }

    #[test]
    #[ignore = "approved run 40571222293 public inventories only; no Docker/network"]
    fn hosted_native_documents_match_summaries_and_current_tuple_criteria() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let reviewed: Value = serde_json::from_str(HOSTED).unwrap();
        for arch in ["amd64", "arm64"] {
            let evidence = &reviewed["architectures"][arch];
            let directory = root.join(format!(".work/approval-hosted/catalog-{arch}"));
            let summary_bytes =
                super::super::release::bytes(&directory.join("summary.json"), 64 * 1024).unwrap();
            assert_eq!(sha256(&summary_bytes), evidence["summary_sha256"]);
            let summary: Value = serde_json::from_slice(&summary_bytes).unwrap();
            assert_eq!(summary["schema"], 1);
            assert_eq!(summary["arch"], arch);
            assert_eq!(summary["source_sha"], HOSTED_REV);
            assert_eq!(summary["status"], "captured-not-release");
            assert_eq!(
                summary["scope"],
                "public native inventory review only; not scan or release acceptance"
            );
            assert_eq!(summary["syft"], HOSTED_SYFT);
            assert_eq!(summary["created"], evidence["created"]);
            let tools = summary["tools"].as_array().unwrap();
            assert_eq!(tools.len(), HISTORICAL.len());
            let mut seen = BTreeSet::new();
            for entry in tools {
                let tool = field(entry, "tool").unwrap();
                assert!(HISTORICAL.contains(&tool) && seen.insert(tool));
                assert_eq!(entry["status"], "captured-not-release");
                assert_eq!(entry["sbom"], format!("{tool}.syft.json"));
                for key in ["config_id", "sbom_sha256"] {
                    assert_eq!(entry[key], evidence["tools"][tool][key]);
                }
                // Capture-time coverage predates this review, so all amd64
                // summaries said blocked. Never treat those labels as approval.
                assert_eq!(
                    entry["coverage"],
                    if arch == "arm64" && POSITIVE.contains(&tool) {
                        "captured-profile"
                    } else {
                        "blocked"
                    }
                );
                let path = directory.join(format!("{tool}.syft.json"));
                let original = super::super::release::bytes(&path, 8 * 1024 * 1024).unwrap();
                assert_eq!(sha256(&original), entry["sbom_sha256"]);
                let document = super::super::release::read_json(&path).unwrap();
                assert_eq!(document["descriptor"]["name"], "syft");
                assert_eq!(document["descriptor"]["version"], "1.55.0");
                assert_eq!(document["schema"]["version"], "16.1.11");
                assert_eq!(
                    document["schema"]["url"],
                    "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.11.json"
                );
                assert_eq!(document["source"]["type"], "image");
                let metadata = &document["source"]["metadata"];
                assert_eq!(metadata["os"], "linux");
                assert_eq!(metadata["architecture"], arch);
                assert_eq!(metadata["imageID"], entry["config_id"]);
                assert_eq!(
                    metadata["labels"]["org.opencontainers.image.revision"],
                    HOSTED_REV
                );
                assert_eq!(
                    metadata["labels"]["org.opencontainers.image.source"],
                    "https://github.com/PRJXAI/devsecops"
                );
                let (config_bytes, config) = embedded_json(&document, "config");
                assert_eq!(
                    format!("sha256:{}", sha256(&config_bytes)),
                    entry["config_id"]
                );
                assert_eq!(config["architecture"], arch);
                assert_eq!(config["os"], "linux");
                assert_eq!(config["config"]["User"], "65532:65532");
                assert_eq!(config["config"]["Labels"], metadata["labels"]);
                assert_eq!(
                    config["config"]["Entrypoint"],
                    if tool == "cargo-audit" {
                        json!(["/usr/local/bin/cargo-audit", "audit"])
                    } else {
                        json!([format!("/usr/local/bin/{tool}")])
                    }
                );
                let (manifest_bytes, manifest) = embedded_json(&document, "manifest");
                assert_eq!(
                    format!("sha256:{}", sha256(&manifest_bytes)),
                    metadata["manifestDigest"]
                );
                assert_eq!(manifest["config"]["digest"], entry["config_id"]);
                assert_eq!(manifest["config"]["size"], config_bytes.len());
                assert_eq!(document["source"]["version"], metadata["manifestDigest"]);
                assert_eq!(
                    format!("sha256:{}", field(&document["source"], "id").unwrap()),
                    metadata["manifestDigest"]
                );
                assert_eq!(
                    document["descriptor"]["configuration"]["search"]["scope"],
                    "all-layers"
                );
                super::super::release::no_scan_diagnostics(&document).unwrap();
                let observed = observations(&document, tool);
                let expected = &reviewed["profiles"][tool];
                assert_eq!(observed["missing"], json!([]), "{arch}/{tool}");
                assert_eq!(observed["required_tuples"], expected["required_tuples"]);
                let mut compilers: Vec<Value> = expected["compilers"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(path, version)| json!([path, version]))
                    .collect();
                let additional = if tool == "kind" {
                    compilers.insert(0, json!(["/usr/local/bin/docker", "go1.26.10"]));
                    json!([
                        [
                            "go-module",
                            "github.com/docker/cli/cmd/docker",
                            "UNKNOWN",
                            "go-module-binary-cataloger",
                            "/usr/local/bin/docker"
                        ],
                        [
                            "go-module",
                            "stdlib",
                            "go1.26.10",
                            "go-module-binary-cataloger",
                            "/usr/local/bin/docker"
                        ]
                    ])
                } else {
                    json!([])
                };
                assert_eq!(observed["additional"], additional, "{arch}/{tool}");
                assert_eq!(observed["compilers"], json!(compilers));
                assert_eq!(
                    observed["compiler_gaps"],
                    if tool == "kind" {
                        json!([["/usr/local/bin/docker", "go1.26.10"]])
                    } else {
                        json!([])
                    }
                );
                let unknown: Vec<_> = observed["unknown"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| row[1].clone())
                    .collect();
                assert_eq!(json!(unknown), expected["unknown"]);
                assert_eq!(
                    observed["profile_result"],
                    match tool {
                        "syft" | "grype" | "gitleaks" => Value::Null,
                        "kind" => json!("Go payload location has no captured compiler inventory"),
                        "cargo-audit" | "cargo-deny" =>
                            json!("Rust payload/dependency/compiler inventory is absent"),
                        _ => json!("UNKNOWN payload/dependency versions block catalog coverage"),
                    }
                );
                // Old base/supplier captures cannot approve current production profiles.
                assert!(check(&document, tool).is_err(), "{arch}/{tool}");
                if POSITIVE.contains(&tool) {
                    // Mutations are disposable negative controls only, never saved
                    // or scanned as substituted/supplemented authentic documents.
                    let path = format!("/usr/local/bin/{tool}");
                    let i = index(&document, "stdlib", &path);
                    let mut changed = document.clone();
                    changed["artifacts"][i]["metadata"]["goCompiledVersion"] = json!("go0.0.0");
                    assert!(check(&changed, tool).is_err());
                    changed = document.clone();
                    changed["artifacts"].as_array_mut().unwrap().remove(i);
                    assert_eq!(
                        check_profile(&changed, tool, &baseline().unwrap()["tools"][tool]),
                        Err(MISSING)
                    );
                    changed = document.clone();
                    changed["artifacts"][i]["version"] = json!("UNKNOWN");
                    assert!(check(&changed, tool).is_err());
                }
                assert_eq!(
                    super::super::release::bytes(&path, 8 * 1024 * 1024).unwrap(),
                    original
                );
            }
        }
    }

    #[test]
    fn production_gitleaks_requires_reviewed_upgrade_not_original_supplier_inventory() {
        let current = profile("gitleaks").unwrap();
        assert_eq!(current["evidence"]["release_accepted"], false);
        assert_eq!(current["compilers"]["/usr/local/bin/gitleaks"], "go1.27.3");
        let mut original = captured("gitleaks");
        let old = &baseline().unwrap()["tools"]["gitleaks"];
        for p in original["artifacts"].as_array_mut().unwrap() {
            if p["type"] == "go-module" {
                let row = old["locations"]["/usr/local/bin/gitleaks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row[1] == p["name"])
                    .unwrap();
                p["version"] = row[2].clone();
                p["metadata"]["goCompiledVersion"] =
                    old["compilers"]["/usr/local/bin/gitleaks"].clone();
            }
        }
        assert!(check_profile(&original, "gitleaks", old).is_ok());
        assert!(check(&original, "gitleaks").is_err());
    }

    #[test]
    #[ignore = "approved run 40683447538 public native candidate captures; no Docker/network"]
    fn upgraded_native_documents_match_production_profile_without_rewriting_reports() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let profile = profile("gitleaks").unwrap();
        for arch in ["amd64", "arm64"] {
            let path = root.join(format!(
                ".work/ctpo-hosted/{arch}/gitleaks-native-candidate-{arch}/gitleaks.syft.json"
            ));
            let original = super::super::release::bytes(&path, 8 * 1024 * 1024).unwrap();
            let bom: Value = serde_json::from_slice(&original).unwrap();
            let identity = &profile["evidence"]["architectures"][arch];
            assert_eq!(sha256(&original), identity["sbom_sha256"]);
            assert_eq!(
                bom["source"]["metadata"]["imageID"],
                identity["config_image"]
            );
            assert_eq!(bom["source"]["metadata"]["architecture"], arch);
            super::super::release::no_scan_diagnostics(&bom).unwrap();
            assert!(check(&bom, "gitleaks").is_ok());
            let mut observed = BTreeSet::new();
            for p in bom["artifacts"].as_array().unwrap() {
                for l in p["locations"].as_array().unwrap() {
                    observed.insert([
                        field(p, "type").unwrap(),
                        field(p, "name").unwrap(),
                        field(p, "version").unwrap(),
                        field(p, "foundBy").unwrap(),
                        field(l, "path").unwrap(),
                    ]);
                }
            }
            let expected: BTreeSet<_> = profile["locations"]
                .as_object()
                .unwrap()
                .iter()
                .flat_map(|(path, rows)| {
                    rows.as_array().unwrap().iter().map(move |r| {
                        [
                            r[0].as_str().unwrap(),
                            r[1].as_str().unwrap(),
                            r[2].as_str().unwrap(),
                            r[3].as_str().unwrap(),
                            path.as_str(),
                        ]
                    })
                })
                .collect();
            assert_eq!(observed, expected);
            assert_eq!(
                super::super::release::bytes(&path, 8 * 1024 * 1024).unwrap(),
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
    fn reviewed_amd64_keeps_every_tuple_compiler_and_unknown_gate() {
        for tool in POSITIVE {
            let mut sbom = captured(tool);
            sbom["source"]["metadata"]["architecture"] = json!("amd64");
            assert_eq!(check(&sbom, tool), Ok(()));
            for i in 0..sbom["artifacts"].as_array().unwrap().len() {
                let mut omitted = sbom.clone();
                omitted["artifacts"].as_array_mut().unwrap().remove(i);
                assert_eq!(check(&omitted, tool), Err(MISSING), "{tool} tuple {i}");
            }
            let i = index(&sbom, "stdlib", &format!("/usr/local/bin/{tool}"));
            for (key, value) in [
                ("version", "UNKNOWN"),
                ("name", "unrelated"),
                ("type", "binary"),
                ("foundBy", "file-cataloger"),
            ] {
                let mut changed = sbom.clone();
                changed["artifacts"][i][key] = json!(value);
                assert!(check(&changed, tool).is_err());
            }
            let mut changed = sbom.clone();
            changed["artifacts"][i]["metadata"]["goCompiledVersion"] = json!("go0.0.0");
            assert!(check(&changed, tool).is_err());
            sbom["artifacts"].as_array_mut().unwrap().push(json!({
                "type":"apk", "name":"extra", "version":"UNKNOWN", "foundBy":"apk-db-cataloger",
                "locations":[{"path":"/usr/lib/apk/db/installed"}]
            }));
            assert_eq!(
                check(&sbom, tool),
                Err("UNKNOWN payload/dependency versions block catalog coverage")
            );
        }
        for tool in INCOMPLETE {
            let mut sbom = captured(tool);
            sbom["source"]["metadata"]["architecture"] = json!("amd64");
            assert_eq!(
                check(&sbom, tool),
                Err("payload coverage lacks reviewed native architecture evidence")
            );
        }
    }

    #[test]
    fn hosted_evidence_is_attribution_not_acceptance_or_new_tuple_criteria() {
        let evidence: Value = serde_json::from_str(HOSTED).unwrap();
        assert_eq!(evidence["run"], 40571222293u64);
        assert_eq!(evidence["source_sha"], HOSTED_REV);
        assert_eq!(evidence["syft"], HOSTED_SYFT);
        assert_eq!(evidence["syft_schema"], "16.1.11");
        assert_eq!(evidence["status"], "captured-not-release");
        for key in [
            "functional_acceptance",
            "clean_scan_acceptance",
            "release_acceptance",
        ] {
            assert_eq!(evidence[key], false);
        }
        for tool in HISTORICAL {
            let profile = &evidence["profiles"][tool];
            assert_eq!(
                profile["compilers"],
                baseline().unwrap()["tools"][tool]["compilers"]
            );
            assert_eq!(
                profile["result"],
                if POSITIVE.contains(tool) {
                    "captured-profile"
                } else {
                    "blocked"
                }
            );
        }
        assert_eq!(evidence["architectures"].as_object().unwrap().len(), 2);
        for (arch, runner) in [("amd64", "ubuntu-24.04"), ("arm64", "ubuntu-24.04-arm")] {
            let capture = &evidence["architectures"][arch];
            assert_eq!(capture["runner"], runner);
            assert_eq!(capture["artifact"], format!("catalog-evidence-{arch}"));
            assert_eq!(capture["summary_sha256"].as_str().unwrap().len(), 64);
            assert_eq!(capture["tools"].as_object().unwrap().len(), 9);
            for tool in HISTORICAL {
                let record = &capture["tools"][tool];
                assert_eq!(record["sbom_sha256"].as_str().unwrap().len(), 64);
                assert_eq!(record["config_id"].as_str().unwrap().len(), 71);
                assert!(record["config_id"].as_str().unwrap().starts_with("sha256:"));
            }
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
            // Kind's old binary-only capture stays historical evidence, not
            // approval for its newly added Docker provider executable.
            let historical = if tool == "kind" {
                "captured"
            } else {
                "blocked"
            };
            assert_eq!(baseline().unwrap()["tools"][tool]["catalog"], historical);
            if tool == "kind" {
                assert_eq!(
                    check(&sbom, tool),
                    Err("kind Docker provider payload inventory has not been reviewed")
                );
            }
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
        let sbom = captured("syft");
        for pointer in [
            "/source/metadata/architecture",
            "/source/metadata/os",
            "/source/type",
            "/descriptor/name",
            "/descriptor/version",
            "/schema/version",
        ] {
            for value in [
                Value::Null,
                json!("riscv64"),
                json!("x86_64"),
                json!("unreviewed"),
            ] {
                let mut changed = sbom.clone();
                *changed.pointer_mut(pointer).unwrap() = value;
                assert!(check(&changed, "syft").is_err(), "{pointer}");
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
