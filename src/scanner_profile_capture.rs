//! Fixed read-only capture proposal for the two repaired scanners; no risk-policy output.
use crate::{
    Result,
    release::{hash, mkdir, read_json, text, write_json},
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

#[test]
#[ignore = "requires four unchanged native catalogs from hosted run 43730804248; proposals only"]
fn capture_repaired_scanner_profiles() -> Result<()> {
    const SOURCE: &str = "d3b870dbb18148fcf71d0ea0986a2eed2b484872";
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let input = root.join(".work/security-repair-captures");
    let output = root.join(".work/security-repair-profile-proposal");
    if output.exists() {
        return Err("refusing existing profile proposal");
    }
    mkdir(&output, false)?;
    let mut profiles = serde_json::Map::new();
    for (tool, hashes) in [
        (
            "syft",
            [
                "da65d45f9ecb47041cb8f8e0fc68eb8270786113e4df043f9d3dd20c90ebf45c",
                "6bea8858bafe08aa45584612775899c56f6985d779dee7e79446fedf48afd4be",
            ],
        ),
        (
            "grype",
            [
                "c168cea4d612a5e4637e026c0591f8d19a6dc337849cfe62afef37f01ae9dde8",
                "a3fc72043c332d73043837035e792c3f9bb4b35c23c52d7fd131914b0312daeb",
            ],
        ),
    ] {
        let mut reference = None;
        let mut evidence = Vec::new();
        for (arch, expected) in ["amd64", "arm64"].into_iter().zip(hashes) {
            let file = input.join(format!("{tool}-{arch}/{tool}.syft.json"));
            if hash(&file, 8 * 1024 * 1024)? != expected {
                return Err("changed native capture");
            }
            let catalog = read_json(&file)?;
            let metadata = &catalog["source"]["metadata"];
            if metadata["architecture"] != arch
                || metadata["os"] != "linux"
                || metadata["labels"]["org.opencontainers.image.revision"] != SOURCE
                || metadata["labels"]["org.opencontainers.image.source"]
                    != "https://github.com/PRJXAI/devsecops"
            {
                return Err("foreign native capture");
            }
            let mut locations = BTreeMap::<String, BTreeSet<Vec<String>>>::new();
            let mut compilers = BTreeMap::<String, String>::new();
            for package in catalog["artifacts"]
                .as_array()
                .ok_or("missing native artifacts")?
            {
                let row = ["type", "name", "version", "foundBy"]
                    .into_iter()
                    .map(|key| text(package, &format!("/{key}")).map(str::to_owned))
                    .collect::<Result<Vec<_>>>()?;
                if row[2].eq_ignore_ascii_case("UNKNOWN") {
                    return Err("unknown native version");
                }
                for location in package["locations"]
                    .as_array()
                    .ok_or("missing native locations")?
                {
                    let path = text(location, "/path")?.to_owned();
                    locations
                        .entry(path.clone())
                        .or_default()
                        .insert(row.clone());
                    if package["type"] == "go-module" {
                        let compiler = text(&package["metadata"], "/goCompiledVersion")?;
                        if compiler != "go1.27.4" {
                            return Err("foreign native Go compiler");
                        }
                        compilers.insert(path, compiler.into());
                    }
                }
            }
            let profile = json!({"locations":locations,"compilers":compilers});
            if reference.as_ref().is_some_and(|old| *old != profile) {
                return Err("native repaired profiles differ");
            }
            reference = Some(profile);
            evidence.push(json!({"arch":arch,"source_sha":SOURCE,"run":43730804248u64,"sbom_sha256":expected,"config_id":metadata["imageID"]}));
        }
        let mut profile = reference.ok_or("missing native profile")?;
        profile["evidence"] = json!(evidence);
        profiles.insert(tool.into(), profile);
    }
    write_json(
        &output.join("proposed-scanner-production.json"),
        &json!({"schema":1,"tools":profiles}),
    )
}
