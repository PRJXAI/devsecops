//! Owner-selected current-stack acceptance, not scanner suppression or a clean claim.
//! Exact snapshot and separate Gitleaks rule; see docs/security.md. New matches block.
use super::{Result, SEVERITIES, text, tool_identity};
use serde_json::{Value, json};
#[cfg(test)]
#[path = "risk_snapshot_capture.rs"]
mod capture;

pub(super) const POLICY: &str = "owner-selected-stack-2026-10-30-v1";

fn snapshot(tool: &str) -> Result<Option<Value>> {
    let all: Value = serde_json::from_str(include_str!("../inventory/accepted-risks.json"))
        .map_err(|_| "invalid accepted-risk snapshot")?;
    let Some(profile) = all["tools"].get(tool) else {
        return Ok(None);
    };
    let recipe: &[u8] = match tool {
        "syft" => include_bytes!("../images/syft/Dockerfile"),
        "grype" => include_bytes!("../images/grype/Dockerfile"),
        _ => return Err("unsupported accepted-risk snapshot tool"),
    };
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(recipe)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if all["schema"] != 1
        || all["decision"] != "owner-selected-stack-2026-10-30"
        || profile["recipe_sha256"] != digest
    {
        return Err("accepted-risk recipe scope changed");
    }
    Ok(Some(profile.clone()))
}

pub(super) fn projection(finding: &Value, package: &Value) -> Result<Value> {
    let mut paths = package["locations"]
        .as_array()
        .ok_or("missing risk package locations")?
        .iter()
        .map(|v| {
            v["path"]
                .as_str()
                .map(str::to_owned)
                .ok_or("invalid risk package location")
        })
        .collect::<Result<Vec<_>>>()?;
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Err("missing risk package locations");
    }
    let mut related=finding["relatedVulnerabilities"].as_array().ok_or("missing related advisory coverage")?.iter().map(|v|json!({"id":v["id"],"namespace":v["namespace"],"severity":v["severity"],"fix":v["fix"]})).collect::<Vec<_>>();
    related.sort_by_key(Value::to_string);
    let v = &finding["vulnerability"];
    Ok(
        json!({"package":{"name":package["name"],"version":package["version"],"type":package["type"],"locations":paths},"vulnerability":{"id":v["id"],"namespace":v["namespace"],"severity":v["severity"],"fix":v["fix"]},"related":related}),
    )
}
fn scope_matches(rule: &Value, package: &Value) -> bool {
    let finding = json!({"vulnerability":rule["identity"]["vulnerability"],"relatedVulnerabilities":rule["identity"]["related"]});
    projection(&finding, package).is_ok_and(|value| value == rule["identity"])
}
const EXCEPTION: &str = "gitleaks-openpgp-no-fix-v1";
const PACKAGE: &str = "golang.org/x/crypto";
const VERSION: &str = "v0.58.0";
const LOCATION: &str = "/usr/local/bin/gitleaks";

// A single known supplier warning, not a prefix/regex exception for arbitrary
// diagnostics. Only the timestamp's four decimal digits are variable.
const PRECISION: &str = "]  WARN go binary packages were found but none carry function symbols; go vulnerability matching falls back to module granularity and may report false positives. if scanning an SBOM, regenerate it with symbol capture enabled for more precise results.\n";

pub(super) fn diagnostics(data: &[u8]) -> Result<&'static str> {
    if data.is_empty() {
        return Ok("none");
    }
    if data.len() == 5 + PRECISION.len()
        && data[0] == b'['
        && data[1..5].iter().all(u8::is_ascii_digit)
        && &data[5..] == PRECISION.as_bytes()
    {
        return Ok("go-module-granularity");
    }
    Err("scanner emitted diagnostics; private logs retained")
}

fn package_matches(package: &Value) -> bool {
    package["name"] == PACKAGE
        && package["version"] == VERSION
        && package["type"] == "go-module"
        && package["locations"].as_array().is_some_and(|locations| {
            !locations.is_empty()
                && locations
                    .iter()
                    .all(|location| location["path"] == LOCATION)
        })
}

fn eligible(tool: &str, finding: &Value, package: &Value) -> bool {
    tool == "gitleaks"
        && package_matches(package)
        && finding["vulnerability"]["id"] == "GO-2026-5932"
        && finding["vulnerability"]["namespace"] == "govulndb:language:go"
        && finding["vulnerability"]["severity"] == "Unknown"
        && finding["relatedVulnerabilities"].as_array().is_some_and(Vec::is_empty)
        // Empty state is the observed pinned presenter value. Missing/unknown/
        // wont-fix/fixed states require review, not optimistic inference.
        && finding["vulnerability"]["fix"]["state"] == ""
        && finding["vulnerability"]["fix"]["versions"].as_array().is_some_and(Vec::is_empty)
}

/// Called only after complete report/source/DB/package/count validation.
/// Rechecking relevant identities here keeps the acceptance boundary explicit.
pub(super) fn assess(tool: &str, sbom: &Value, report: &Value) -> Result<Value> {
    tool_identity(tool)?;
    let packages = sbom["artifacts"]
        .as_array()
        .ok_or("missing risk inventory")?;
    let profile = snapshot(tool)?;
    let mut used = std::collections::BTreeMap::<String, u64>::new();
    let (mut accepted, mut blocking) = (0u64, 0u64);
    for key in ["matches", "ignoredMatches"] {
        let findings = match report.get(key) {
            None if key == "ignoredMatches" => continue,
            Some(Value::Array(findings)) => findings,
            _ => return Err("missing or malformed vulnerability matches"),
        };
        for finding in findings {
            let artifact = &finding["artifact"];
            let id = text(artifact, "/id")?;
            let package = packages
                .iter()
                .find(|package| package["id"] == id)
                .ok_or("finding package absent from SBOM")?;
            for key in ["name", "version", "type"] {
                if artifact.get(key) != package.get(key) {
                    return Err("finding package identity mismatch");
                }
            }
            if accepted == 0 && eligible(tool, finding, package) {
                accepted += 1;
            } else if let Some(rule) = profile
                .as_ref()
                .and_then(|p| p["rules"].as_array())
                .and_then(|rules| {
                    rules.iter().find(|rule| {
                        projection(finding, package).is_ok_and(|v| v == rule["identity"])
                    })
                })
            {
                let id = rule["id"]
                    .as_str()
                    .ok_or("invalid risk snapshot rule")?
                    .to_owned();
                let count = used.entry(id).or_default();
                if *count
                    < rule["maximum_occurrences"]
                        .as_u64()
                        .ok_or("invalid risk occurrence limit")?
                {
                    *count += 1;
                    accepted += 1;
                } else {
                    blocking += 1;
                }
            } else {
                blocking += 1;
            }
        }
    }
    Ok(
        json!({"policy":POLICY,"accepted":accepted,"blocking":blocking,
        "exceptions":if accepted > 0 { vec![if let Some(profile) = profile.as_ref() { profile["acceptance_id"].as_str().ok_or("missing acceptance identity")? } else { EXCEPTION }] } else { vec![] }}),
    )
}

pub(super) fn status(decision: &Value) -> &'static str {
    if decision["blocking"].as_u64() != Some(0) {
        "findings"
    } else if decision["accepted"].as_u64() == Some(0) {
        "clean"
    } else {
        "accepted-risk"
    }
}

/// Independently validate public receipt accounting; no arbitrary reported
/// exception name, severity or suppression can turn into publication permission.
pub(super) fn receipt(value: &Value, tool: &str) -> Result<()> {
    tool_identity(tool)?;
    let counts = value["counts"]
        .as_object()
        .ok_or("missing receipt counts")?;
    if counts.len() != SEVERITIES.len() {
        return Err("receipt has missing severity coverage");
    }
    let mut total = 0u64;
    for severity in &SEVERITIES[..6] {
        total = total
            .checked_add(
                counts
                    .get(*severity)
                    .and_then(Value::as_u64)
                    .ok_or("invalid receipt severity count")?,
            )
            .ok_or("receipt count overflow")?;
    }
    let ignored = counts
        .get("ignoredMatches")
        .and_then(Value::as_u64)
        .ok_or("invalid receipt suppression count")?;
    let risk = &value["risk"];
    if risk.as_object().is_none_or(|fields| fields.len() != 4)
        || risk["policy"] != POLICY
        || risk["blocking"].as_u64() != Some(0)
        || value["count"].as_u64() != Some(total)
        || ignored > total
        || risk["accepted"].as_u64() != Some(total)
        || value["status"].as_str() != Some(status(risk))
        || !["none", "go-module-granularity"].contains(&value["diagnostics"].as_str().unwrap_or(""))
    {
        return Err("receipt risk policy or accounting mismatch");
    }
    let expected = if total == 0 {
        json!([])
    } else if total == 1 && tool == "gitleaks" && counts["Unknown"].as_u64() == Some(1) {
        json!([EXCEPTION])
    } else if let Some(profile) = snapshot(tool)? {
        let mut allowed = std::collections::BTreeMap::<&str, u64>::new();
        for rule in profile["rules"]
            .as_array()
            .ok_or("missing accepted-risk rules")?
        {
            let severity = rule["identity"]["vulnerability"]["severity"]
                .as_str()
                .ok_or("invalid accepted-risk severity")?;
            *allowed.entry(severity).or_default() += rule["maximum_occurrences"]
                .as_u64()
                .ok_or("invalid accepted-risk limit")?;
        }
        if SEVERITIES[..6]
            .iter()
            .any(|s| counts[*s].as_u64().unwrap_or(u64::MAX) > *allowed.get(s).unwrap_or(&0))
        {
            return Err("receipt exceeds reviewed risk snapshot");
        }
        json!([profile["acceptance_id"]])
    } else {
        return Err("receipt contains unapproved findings");
    };
    if risk["exceptions"] != expected {
        return Err("receipt contains unapproved exception identities");
    }
    Ok(())
}

pub(super) fn inventory(value: &Value, tool: &str, sbom: &Value) -> Result<()> {
    receipt(value, tool)?;
    if value["risk"]["accepted"] == 0 {
        return Ok(());
    }
    if let Some(profile) = snapshot(tool)? {
        let packages = sbom["artifacts"]
            .as_array()
            .ok_or("missing risk inventory")?;
        for rule in profile["rules"]
            .as_array()
            .ok_or("missing accepted-risk rules")?
        {
            if !packages.iter().any(|p| scope_matches(rule, p)) {
                return Err("accepted snapshot package differs from verified SBOM");
            }
        }
    } else if value["risk"]["accepted"] == 1 {
        let packages = sbom["artifacts"]
            .as_array()
            .ok_or("missing risk inventory")?;
        if packages
            .iter()
            .filter(|package| package_matches(package))
            .count()
            != 1
        {
            return Err("accepted risk package differs from verified SBOM");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn package() -> Value {
        json!({"id":"package","name":PACKAGE,"version":VERSION,"type":"go-module","locations":[{"path":LOCATION}]})
    }
    fn finding() -> Value {
        json!({"artifact":package(),"relatedVulnerabilities":[],"vulnerability":{"id":"GO-2026-5932","namespace":"govulndb:language:go","severity":"Unknown","fix":{"state":"","versions":[]}}})
    }
    fn sbom() -> Value {
        json!({"artifacts":[package()]})
    }
    fn accepted() -> Value {
        json!({"count":1,"counts":SEVERITIES.into_iter().map(|key|(key, u64::from(key == "Unknown"))).collect::<std::collections::BTreeMap<_,_>>(),
            "risk":assess("gitleaks", &sbom(), &json!({"matches":[finding()]})).unwrap(),"status":"accepted-risk","diagnostics":"go-module-granularity"})
    }

    #[test]
    fn exact_nofix_match_is_visible_and_accepted_not_clean() {
        for key in ["matches", "ignoredMatches"] {
            let mut report = json!({"matches":[]});
            report[key] = json!([finding()]);
            let decision = assess("gitleaks", &sbom(), &report).unwrap();
            assert_eq!(decision["accepted"], 1);
            assert_eq!(decision["blocking"], 0);
            assert_eq!(status(&decision), "accepted-risk");
        }
        let mut receipt = accepted();
        assert!(inventory(&receipt, "gitleaks", &sbom()).is_ok());
        receipt["counts"]["ignoredMatches"] = json!(1);
        assert!(inventory(&receipt, "gitleaks", &sbom()).is_ok());
        let clean = assess("gitleaks", &sbom(), &json!({"matches":[]})).unwrap();
        assert_eq!(status(&clean), "clean");
    }

    #[test]
    fn no_fix_is_not_a_blanket_exception_and_new_fixes_revoke_acceptance() {
        for (pointer, value) in [
            ("/vulnerability/id", json!("GO-other")),
            ("/vulnerability/namespace", json!("other")),
            ("/vulnerability/severity", json!("High")),
            ("/relatedVulnerabilities", json!([{"id":"new-alias"}])),
            ("/relatedVulnerabilities", Value::Null),
            ("/vulnerability/fix", Value::Null),
            ("/vulnerability/fix/state", json!("fixed")),
            ("/vulnerability/fix/state", json!("not-fixed")),
            ("/vulnerability/fix/versions", json!(["v0.59.0"])),
            ("/vulnerability/fix/versions", Value::Null),
        ] {
            let mut bad = finding();
            *bad.pointer_mut(pointer).unwrap() = value;
            let decision = assess("gitleaks", &sbom(), &json!({"matches":[bad]})).unwrap();
            assert_eq!(decision["accepted"], 0, "{pointer}");
            assert_eq!(decision["blocking"], 1, "{pointer}");
        }
        for tool in ["syft", "grype", "docker", "cargo-deny"] {
            assert_eq!(
                assess(tool, &sbom(), &json!({"matches":[finding()]})).unwrap()["blocking"],
                1
            );
        }
        let decision = assess(
            "gitleaks",
            &sbom(),
            &json!({"matches":[finding()],"ignoredMatches":[finding()]}),
        )
        .unwrap();
        assert_eq!(decision["accepted"], 1);
        assert_eq!(decision["blocking"], 1);
        assert_eq!(status(&decision), "findings");
    }

    #[test]
    fn changed_dependency_or_location_cannot_borrow_the_exception() {
        for (pointer, value) in [
            ("/name", json!("another-module")),
            ("/version", json!("v0.35.0")),
            ("/type", json!("rpm")),
            ("/locations/0/path", json!("/usr/local/bin/other")),
            ("/locations", json!([])),
            ("/locations", json!([{"path":LOCATION},{"path":"/other"}])),
        ] {
            let mut package = package();
            *package.pointer_mut(pointer).unwrap() = value;
            let mut finding = finding();
            finding["artifact"] = package.clone();
            let bom = json!({"artifacts":[package]});
            assert_eq!(
                assess("gitleaks", &bom, &json!({"matches":[finding]})).unwrap()["blocking"],
                1
            );
            assert!(inventory(&accepted(), "gitleaks", &bom).is_err());
        }
    }

    #[test]
    fn receipt_never_accepts_hidden_counts_unknown_policy_or_a_clean_label() {
        for (pointer, value) in [
            ("/count", json!(0)),
            ("/counts/High", json!(1)),
            ("/counts/Unknown", json!(0)),
            ("/counts/ignoredMatches", json!(2)),
            ("/risk/policy", json!("old-policy")),
            ("/risk/blocking", json!(1)),
            ("/risk/accepted", json!(0)),
            ("/risk/exceptions", json!(["other"])),
            ("/status", json!("clean")),
            ("/diagnostics", json!("anything")),
        ] {
            let mut bad = accepted();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(receipt(&bad, "gitleaks").is_err(), "{pointer}");
        }
        assert!(receipt(&accepted(), "syft").is_err());
        let mut bad = accepted();
        bad["counts"].as_object_mut().unwrap().remove("Negligible");
        assert!(receipt(&bad, "gitleaks").is_err());
        let mut bad = accepted();
        bad["counts"]["High"] = json!(u64::MAX);
        assert!(receipt(&bad, "gitleaks").is_err());
    }

    #[test]
    fn selected_stack_accepts_only_the_reviewed_snapshot_and_preserves_counts() {
        for tool in ["syft", "grype"] {
            let p = snapshot(tool).unwrap().unwrap();
            let mut packages = Vec::new();
            let mut findings = Vec::new();
            let mut counts = SEVERITIES
                .into_iter()
                .map(|s| (s.to_owned(), 0u64))
                .collect::<std::collections::BTreeMap<_, _>>();
            for (n, r) in p["rules"].as_array().unwrap().iter().enumerate() {
                let mut package = r["identity"]["package"].clone();
                package["id"] = json!(n.to_string());
                package["locations"] = json!(
                    package["locations"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|path| json!({"path":path}))
                        .collect::<Vec<_>>()
                );
                for _ in 0..r["maximum_occurrences"].as_u64().unwrap() {
                    findings.push(json!({"artifact":package,"vulnerability":r["identity"]["vulnerability"],"relatedVulnerabilities":r["identity"]["related"]}));
                    *counts
                        .get_mut(r["identity"]["vulnerability"]["severity"].as_str().unwrap())
                        .unwrap() += 1;
                }
                packages.push(package);
            }
            let bom = json!({"artifacts":packages});
            let raw = json!({"matches":findings});
            let assessment = assess(tool, &bom, &raw).unwrap();
            let total = raw["matches"].as_array().unwrap().len();
            assert_eq!(assessment["accepted"], total);
            assert_eq!(assessment["blocking"], 0);
            let receipt = json!({"count":total,"counts":counts,"risk":assessment,"status":"accepted-risk","diagnostics":"none"});
            assert!(inventory(&receipt, tool, &bom).is_ok());
            let mut duplicate = raw.clone();
            duplicate["matches"]
                .as_array_mut()
                .unwrap()
                .push(raw["matches"][0].clone());
            assert_eq!(assess(tool, &bom, &duplicate).unwrap()["blocking"], 1);
            for (pointer, value) in [
                ("/vulnerability/id", json!("new-advisory")),
                ("/vulnerability/severity", json!("Low")),
                ("/vulnerability/fix/versions", json!(["new-fix"])),
                ("/relatedVulnerabilities", json!([])),
            ] {
                let mut changed = raw.clone();
                if changed["matches"][0].pointer(pointer) == Some(&value) {
                    continue;
                }
                *changed["matches"][0].pointer_mut(pointer).unwrap() = value;
                assert_eq!(
                    assess(tool, &bom, &changed).unwrap()["blocking"],
                    1,
                    "{tool}/{pointer}"
                );
            }
            let mut changed = bom.clone();
            for package in changed["artifacts"].as_array_mut().unwrap() {
                package["locations"][0]["path"] = json!("/other");
            }
            assert!(inventory(&receipt, tool, &changed).is_err());
            let mut changed = receipt.clone();
            changed["status"] = json!("clean");
            assert!(super::receipt(&changed, tool).is_err());
        }
    }
    #[test]
    fn medium_x509_risk_acceptance_is_exact_and_not_a_severity_waiver() {
        for tool in ["syft", "grype"] {
            let package = json!({"id":"stdlib","name":"stdlib","version":"go1.26.8","type":"go-module","locations":[{"path":format!("/usr/local/bin/{tool}")}]});
            let finding = json!({
                "artifact":package,
                "vulnerability":{
                    "id":"GO-2026-6809","namespace":"govulndb:language:go","severity":"Medium",
                    "fix":{"state":"fixed","versions":["1.26.10","1.27.3"],"available":[
                        {"date":"2026-10-20","kind":"release","version":"1.26.10"},
                        {"date":"2026-10-20","kind":"release","version":"1.27.3"}
                    ]}
                },
                "relatedVulnerabilities":[{"id":"CVE-2026-111943","namespace":"nvd:cpe","severity":"Medium","fix":null}]
            });
            let bom = json!({"artifacts":[package]});
            let profile = snapshot(tool).unwrap().unwrap();
            let identity = projection(&finding, &package).unwrap();
            let rule = profile["rules"]
                .as_array()
                .unwrap()
                .iter()
                .find(|rule| rule["identity"] == identity)
                .unwrap();
            use sha2::{Digest, Sha256};
            let expected_id = Sha256::digest(identity.to_string().as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert_eq!(rule["id"], expected_id);
            assert_eq!(rule["maximum_occurrences"], 1);
            for key in ["matches", "ignoredMatches"] {
                let mut report = json!({"matches":[]});
                report[key] = json!([finding]);
                let decision = assess(tool, &bom, &report).unwrap();
                assert_eq!(decision["accepted"], 1);
                assert_eq!(decision["blocking"], 0);
                assert_eq!(status(&decision), "accepted-risk");
            }
            for (pointer, value) in [
                ("/vulnerability/severity", json!("Unknown")),
                ("/vulnerability/severity", json!("High")),
                ("/relatedVulnerabilities/0/severity", json!("Unknown")),
                ("/relatedVulnerabilities/0/severity", json!("High")),
                ("/relatedVulnerabilities/0/id", json!("CVE-other")),
                ("/vulnerability/id", json!("GO-other")),
                ("/vulnerability/fix/state", json!("not-fixed")),
                ("/vulnerability/fix/versions", json!(["1.26.11"])),
                ("/vulnerability/fix/available/0/date", json!("2026-10-21")),
            ] {
                let mut changed = finding.clone();
                *changed.pointer_mut(pointer).unwrap() = value;
                let decision = assess(tool, &bom, &json!({"matches":[changed]})).unwrap();
                assert_eq!(decision["accepted"], 0, "{tool}/{pointer}");
                assert_eq!(decision["blocking"], 1, "{tool}/{pointer}");
            }
            for (pointer, value) in [
                ("/name", json!("other")),
                ("/version", json!("go1.26.9")),
                ("/type", json!("rpm")),
                ("/locations/0/path", json!("/other")),
            ] {
                let mut changed_package = package.clone();
                *changed_package.pointer_mut(pointer).unwrap() = value;
                let mut changed = finding.clone();
                changed["artifact"] = changed_package.clone();
                let decision = assess(
                    tool,
                    &json!({"artifacts":[changed_package]}),
                    &json!({"matches":[changed]}),
                )
                .unwrap();
                assert_eq!(decision["blocking"], 1, "{tool}/{pointer}");
            }
            let duplicate = assess(
                tool,
                &bom,
                &json!({"matches":[finding],"ignoredMatches":[finding]}),
            )
            .unwrap();
            assert_eq!(duplicate["accepted"], 1);
            assert_eq!(duplicate["blocking"], 1);
            assert_eq!(status(&duplicate), "findings");
            assert_eq!(
                assess("gitleaks", &bom, &json!({"matches":[finding]})).unwrap()["blocking"],
                1
            );
        }
    }

    #[test]
    #[ignore = "fixed private 2026-10-31 arm64 production catalog rescan replay; no Docker/network/publication"]
    fn recorded_medium_x509_rescans_pass_only_as_accepted_risk() -> Result<()> {
        use crate::release::{
            JSON_LIMIT, db_status, hash, read_json, report_counts, sbom_packages,
        };
        use chrono::DateTime;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for (tool, bom_hash, report_hash, expected, high, medium) in [
            (
                "syft",
                "9b8d99a143f09560a74f3cf18aa0679fb23dc16668f2df763e561f435962e1a1",
                "c89022a31c78b6726796fc3aa33adf62a3e52ba41e9dcfe1f2f1527f1a1becb6",
                18,
                10,
                3,
            ),
            (
                "grype",
                "8c877b67421736212305d96acde99e96b793d2be6bb544caee0bb902b190c548",
                "cb269e7fef8cdcc63e3535d7cd66e1be8426fb83218e4a344495388870a66083",
                23,
                13,
                5,
            ),
        ] {
            let input = root.join(format!(
                ".work/delivery-20261030/{tool}-published-arm64/{tool}.syft.json"
            ));
            let output = root.join(format!(".work/risk-review-20261031/{tool}.grype.json"));
            assert_eq!(hash(&input, JSON_LIMIT)?, bom_hash);
            assert_eq!(hash(&output, JSON_LIMIT)?, report_hash);
            let bom = read_json(&input)?;
            let report = read_json(&output)?;
            let at = DateTime::parse_from_rfc3339(text(&report, "/descriptor/timestamp")?)
                .map_err(|_| "invalid recorded scan timestamp")?
                .with_timezone(&chrono::Utc);
            let db = &report["descriptor"]["db"]["status"];
            db_status(db, at)?;
            let packages = sbom_packages(&bom, text(&bom, "/source/metadata/imageID")?, "arm64")?;
            crate::coverage::check(&bom, tool)?;
            let counts = report_counts(&bom, &packages, &report, db, at)?;
            assert_eq!(counts["Critical"], 2);
            assert_eq!(counts["High"], high);
            assert_eq!(counts["Medium"], medium);
            assert_eq!(counts["Unknown"], 3);
            assert_eq!(counts["ignoredMatches"], 0);
            let decision = assess(tool, &bom, &report)?;
            assert_eq!(decision["accepted"], expected);
            assert_eq!(decision["blocking"], 0);
            assert_eq!(status(&decision), "accepted-risk");
            assert_eq!(report["matches"].as_array().unwrap().len(), expected);
        }
        Ok(())
    }

    #[test]
    fn precision_warning_is_exact_and_other_diagnostics_still_fail() {
        assert_eq!(diagnostics(b""), Ok("none"));
        let known = format!("[0000{PRECISION}");
        assert_eq!(diagnostics(known.as_bytes()), Ok("go-module-granularity"));
        for bad in [
            format!("{known}{known}"),
            format!("{known}other\n"),
            format!(" {known}"),
            known.replace("WARN", "ERROR"),
            known.replace("0000", "abcd"),
            known.replace("module granularity", "other"),
            known.trim_end().to_string(),
        ] {
            assert!(diagnostics(bad.as_bytes()).is_err());
        }
        assert!(diagnostics(&[255]).is_err());
    }
}
