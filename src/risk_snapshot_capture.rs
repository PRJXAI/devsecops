//! One explicit owner-approved snapshot; this fixture never edits active policy.
use super::*;
use crate::release::{hash, read_json, write_json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

fn rules(report: &Value, catalog: &Value, relocate: Option<&str>) -> Result<Vec<Value>> {
    let mut rows = BTreeMap::<String, (Value, u64)>::new();
    for key in ["matches", "ignoredMatches"] {
        for raw in report[key].as_array().into_iter().flatten() {
            let finding = raw.get("match").unwrap_or(raw);
            let mut package = catalog["artifacts"]
                .as_array()
                .ok_or("missing snapshot artifacts")?
                .iter()
                .find(|p| p["id"] == finding["artifact"]["id"])
                .ok_or("foreign snapshot package")?
                .clone();
            if let Some(path) = relocate {
                package["locations"] = json!([{"path":path}]);
            }
            let identity = projection(finding, &package)?;
            let key = identity.to_string();
            let row = rows.entry(key).or_insert((identity, 0));
            row.1 += 1;
        }
    }
    use sha2::{Digest, Sha256};
    Ok(rows.into_iter().map(|(key,(identity,count))|json!({"id":Sha256::digest(key.as_bytes()).iter().map(|b|format!("{b:02x}")).collect::<String>(),"identity":identity,"maximum_occurrences":count})).collect())
}
#[test]
#[ignore = "fixed 2026-10-30 owner acceptance capture; writes proposals only; no Docker or registry writes"]
fn capture_reviewed_current_stack() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let consumer = root.join("../obsidian-sync");
    let output = root.join(".work/delivery-20261030");
    let mut production = serde_json::Map::new();
    let mut profiles = serde_json::Map::new();
    for (tool, index) in [("syft", 1), ("grype", 0)] {
        let mut reference = None;
        let mut evidence = Vec::new();
        for arch in ["amd64", "arm64"] {
            let file = root.join(format!(
                ".work/delivery-20261030/catalog-{tool}-{arch}/{tool}.syft.json"
            ));
            let catalog = read_json(&file)?;
            if catalog["source"]["metadata"]["labels"]["org.opencontainers.image.revision"]
                != "aaab990627e8f73fb89c5807193092324e3d004d"
                || catalog["source"]["metadata"]["architecture"] != arch
            {
                return Err("unreviewed source/native catalog");
            }
            let mut locations = BTreeMap::<String, BTreeSet<Vec<String>>>::new();
            let mut compilers = BTreeMap::<String, String>::new();
            for p in catalog["artifacts"].as_array().ok_or("missing artifacts")? {
                for l in p["locations"].as_array().ok_or("missing locations")? {
                    let path = text(l, "/path")?.to_owned();
                    let row = ["type", "name", "version", "foundBy"]
                        .into_iter()
                        .map(|key| text(p, &format!("/{key}")).map(str::to_owned))
                        .collect::<Result<Vec<_>>>()?;
                    if row[2].eq_ignore_ascii_case("UNKNOWN") {
                        return Err("unknown native inventory version");
                    }
                    locations.entry(path.clone()).or_default().insert(row);
                    if p["type"] == "go-module" {
                        compilers.insert(path, text(&p["metadata"], "/goCompiledVersion")?.into());
                    }
                }
            }
            let profile = json!({"locations":locations,"compilers":compilers});
            if reference.as_ref().is_some_and(|old| *old != profile) {
                return Err("native scanner profiles differ");
            }
            reference = Some(profile);
            evidence.push(json!({"arch":arch,"source_sha":"aaab990627e8f73fb89c5807193092324e3d004d","run":41074964808u64,"sbom_sha256":hash(&file,8*1024*1024)?,"config_id":catalog["source"]["metadata"]["imageID"]}));
        }
        let mut profile = reference.ok_or("missing scanner profile")?;
        profile["evidence"] = json!(evidence);
        profiles.insert(tool.into(), profile);
        let path = consumer.join(format!(".work/security/sbom-chain/arm64/image-{index:02}"));
        let report = read_json(&path.with_extension("grype.json"))?;
        let catalog = read_json(&path.with_extension("syft.json"))?;
        let accepted = rules(&report, &catalog, Some(&format!("/usr/local/bin/{tool}")))?;
        production.insert(tool.into(),json!({"acceptance_id":format!("{tool}-stack-2026-10-30"),"recipe_sha256":hash(&root.join(format!("images/{tool}/Dockerfile")),1024*1024)?,"rules":accepted,"reference_report_sha256":hash(&path.with_extension("grype.json"),8*1024*1024)?,"reference_image":catalog["source"]["metadata"]["userInput"],"platforms":["linux/amd64","linux/arm64"]}));
    }
    write_json(
        &output.join("proposed-accepted-risks.json"),
        &json!({"schema":1,"decision":"owner-selected-stack-2026-10-30","authorization":"Repository owner explicitly accepts the investigated current stack risks and requests delivery; includes findings with published fixes. No inventory/runtime/legal proof is inferred.","tools":production}),
    )?;
    write_json(
        &output.join("proposed-scanner-production.json"),
        &json!({"schema":1,"tools":profiles}),
    )?;
    let mut assets = Vec::new();
    for arch in ["amd64", "arm64"] {
        let directory = consumer.join(format!(".work/security/sbom-chain/{arch}"));
        let summary = read_json(&directory.join("summary.json"))?;
        for (n, entry) in summary["images"]
            .as_array()
            .ok_or("missing image summary")?
            .iter()
            .enumerate()
        {
            if entry["status"] == "error" {
                continue;
            }
            let file = directory.join(format!("image-{n:02}"));
            let catalog = read_json(&file.with_extension("syft.json"))?;
            let report = read_json(&file.with_extension("grype.json"))?;
            assets.push(json!({"asset":entry["image"],"platform":format!("linux/{arch}"),"config_id":catalog["source"]["metadata"]["imageID"],"rules":rules(&report,&catalog,None)?,"reference_report_sha256":hash(&file.with_extension("grype.json"),8*1024*1024)?}));
        }
    }
    let catalog = read_json(&consumer.join(".work/sbom/builder.syft.json"))?;
    let report = read_json(&consumer.join(".work/sbom/builder.grype.json"))?;
    assets.push(json!({"asset":"populated-builder","dockerfile_sha256":hash(&consumer.join("Dockerfile"),1024*1024)?,"platforms":["linux/amd64","linux/arm64"],"reference_platform":"linux/arm64","rules":rules(&report,&catalog,None)?,"reference_report_sha256":hash(&consumer.join(".work/sbom/builder.grype.json"),8*1024*1024)?}));
    write_json(
        &output.join("proposed-consumer-risk-acceptance.json"),
        &json!({"schema":1,"decision":"owner-selected-stack-2026-10-30","assets":assets,"inventory_gaps_accepted":false,"runtime_findings_accepted":false,"new_findings_accepted":false}),
    )?;
    Ok(())
}
