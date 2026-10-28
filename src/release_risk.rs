//! Owner-reviewed no-fix acceptance, not scanner suppression or a clean claim.
//! Narrow explicit rule; see docs/release-risk-policy.md. All other matches block.
use super::{Result, SEVERITIES, text, tool_identity};
use serde_json::{Value, json};

pub(super) const POLICY: &str = "reviewed-nofix-2026-10-28-v1";
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
            } else {
                blocking += 1;
            }
        }
    }
    Ok(
        json!({"policy":POLICY,"accepted":accepted,"blocking":blocking,
        "exceptions":if accepted == 1 { vec![EXCEPTION] } else { vec![] }}),
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
    if value["risk"]["accepted"] == 1 {
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
