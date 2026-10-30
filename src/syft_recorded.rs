//! Read-only replay of the first complete binary/paired-scan observation, including blockers.
use super::*;

#[test]
#[ignore = "requires fixed retained local Syft captures; no Docker, retrieval or new scan"]
fn recorded_syft_compiler_observation_preserves_failures_and_all_matches() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let captures = root.join(".work/check-92343-1793306260278154000");
    for (file, expected, limit) in [
        (
            "candidate.tar",
            "cd872a3d7deab6169c679e1cbc7cc1167897f450669de2ac8bae132932857b61",
            TAR_LIMIT,
        ),
        (
            "supplier.tar",
            "d4063de5d5462e7d2831910b3ad1061c571173edc7e440f426290e6a26391450",
            TAR_LIMIT,
        ),
        (
            "candidate.syft.json",
            "4fb5ac76be0cee245b25c9c1222c6111e720880d3af274544483b8f38a21ff1e",
            JSON_LIMIT,
        ),
        (
            "supplier.syft.json",
            "825c0dbfc5cf4cb6339871939dc943a99dfe6999888e9aa07d1b082b40cae56d",
            JSON_LIMIT,
        ),
        (
            "71-stdout.log",
            "9b312f96974212ee5705bfbb74ce26fa150b08515fd171f564b2095379458b23",
            JSON_LIMIT,
        ),
        (
            "82-stdout.log",
            "4ad91e575b62adc07e0debb769fe0dda1733d93af163c52ff2ccc2c15c26de9b",
            JSON_LIMIT,
        ),
        (
            "syft-context/candidate",
            "4c978b11cbeb85dc7148bd7cc57d5b81dbc457bfd2b9b9ee1def1ccb71bc9c6f",
            128 * 1024 * 1024,
        ),
        (
            "syft-context/module-graph.txt",
            "b0554ce324a6721bec87a5fad900a4018f8f64f4d8abb2b25255321759c1c761",
            JSON_LIMIT,
        ),
        (
            "syft-context/imports.txt",
            "5b15b29f32c22aa0ccaefda739169224696197135193985a1171754731041b43",
            JSON_LIMIT,
        ),
        (
            "syft-context/binary-metadata.txt",
            "1fabd4d77b910753240136aae429032ba0bfde8115e6f47432f224d3206be989",
            JSON_LIMIT,
        ),
        (
            "44-stdout.log",
            "6230bbdb9c39d4838a8af21b773284c8808766256c3ce72ffa022134bd852ee3",
            JSON_LIMIT,
        ),
        (
            "44-stderr.log",
            "3c11004af1daf77d3aacf7c74b6bfaa98ffaafdacd5f4f0b2298ad5f18c157ab",
            JSON_LIMIT,
        ),
        (
            "compiler.tar",
            "64bcc4c11e0cb323b987cfe25059337be9b4c873607897390750f20b71e0315c",
            TAR_LIMIT,
        ),
        (
            "85-stdout.log",
            "f239b088db2c302ac04f30f46e288ca818289694581913af23753ebe6a003dcf",
            JSON_LIMIT,
        ),
    ] {
        assert_eq!(hash(&captures.join(file), limit)?, expected);
    }
    let mut observations = BTreeMap::new();
    let mut graphs = BTreeMap::new();
    for (name, compiler, report, expected) in [
        ("candidate", "go1.27.3", "71-stdout.log", 4),
        ("supplier", "go1.26.8", "82-stdout.log", 18),
    ] {
        let config =
            crate::archive::config_digest(&captures.join(format!("{name}.tar")), "arm64", "local")?;
        let catalog = read_json(&captures.join(format!("{name}.syft.json")))?;
        let packages = sbom_packages(&catalog, &config, "arm64")?;
        let raw = read_json(&captures.join(report))?;
        let now = DateTime::parse_from_rfc3339(text(&raw, "/descriptor/timestamp")?)
            .map_err(|_| "invalid captured scan time")?
            .with_timezone(&Utc);
        let db = &raw["descriptor"]["db"]["status"];
        let counts = report_counts(&catalog, &packages, &raw, db, now)?;
        assert_eq!(total(&counts), expected);
        let risk = risk::assess("syft", &catalog, &raw)?;
        assert_eq!(risk["accepted"], 0);
        assert_eq!(risk["blocking"], expected);
        let identities = raw["matches"].as_array().ok_or("missing captured matches")?.iter().map(|m|json!({"package":m["artifact"]["name"],"version":m["artifact"]["version"],"advisory":m["vulnerability"]["id"],"severity":m["vulnerability"]["severity"],"fix":m["vulnerability"]["fix"]})).collect::<Vec<_>>();
        observations.insert(name,json!({"counts":counts,"risk":risk,"findings":identities,"report_sha256":hash(&captures.join(report),JSON_LIMIT)?,"db":db,"original_scan_time":now.to_rfc3339()}));
        graphs.insert(name, super::modules(&catalog, compiler)?);
    }
    let candidate = &graphs["candidate"];
    let supplier = &graphs["supplier"];
    let added = candidate
        .keys()
        .filter(|n| !supplier.contains_key(*n))
        .collect::<Vec<_>>();
    let removed = supplier
        .keys()
        .filter(|n| !candidate.contains_key(*n))
        .collect::<Vec<_>>();
    let changed = candidate
        .iter()
        .filter(|(n, v)| supplier.get(*n).is_some_and(|old| old != *v))
        .map(|(n, v)| json!({"module":n,"before":supplier[n],"after":v}))
        .collect::<Vec<_>>();
    let tests = String::from_utf8(bytes(&captures.join("44-stdout.log"), JSON_LIMIT)?)
        .map_err(|_| "invalid retained test output")?;
    let diagnostics = String::from_utf8(bytes(&captures.join("44-stderr.log"), JSON_LIMIT)?)
        .map_err(|_| "invalid retained test diagnostics")?;
    assert!(tests.lines().any(|line| line.starts_with("FAIL")));
    assert!(diagnostics.contains("no space left on device"));
    assert_eq!(
        regular(&captures.join("85-stdout.log"), JSON_LIMIT)?
            .metadata()
            .unwrap()
            .len(),
        8 * 1024 * 1024
    );
    assert!(read_json(&captures.join("85-stdout.log")).is_err());
    let summary = json!({"schema":1,"arch":"arm64","status":"blocked-experimental-observation","compiler":super::COMPILER,"source_archive_sha256":super::SOURCE_HASH,"go_mod_sha256":super::MOD_HASH,"go_sum_sha256":super::SUM_HASH,"candidate_binary_sha256":"4c978b11cbeb85dc7148bd7cc57d5b81dbc457bfd2b9b9ee1def1ccb71bc9c6f","observations":observations,"module_changes":{"added":added,"removed":removed,"changed":changed},"upstream_race_tests":"failed","test_resource_exhaustion_observed":true,"compiler_input_catalog":"failed-output-limit-no-count","compiler_archive_sha256":"64bcc4c11e0cb323b987cfe25059337be9b4c873607897390750f20b71e0315c","native_inventory_approved":false,"complete_notice_source_provenance_review":false,"release_accepted":false,"replay":"original evidence time; no present-day scan or approval"});
    write_new(
        &root.join(".work/syft-recorded-observation.json"),
        &serde_json::to_vec_pretty(&summary).map_err(|_| "cannot encode recorded observation")?,
        0o600,
    )
}

#[test]
#[ignore = "offline scan of one fixed retained patched binary; keeps failed upstream suite and interrupted run"]
fn recorded_syft_dependency_binary_scan_preserves_all_blockers() -> Result<()> {
    let mut driver = Driver::new()?;
    let (arch, _) = driver.native()?;
    if arch != "arm64" {
        return Err("retained Syft dependency binary is arm64 only");
    }
    let captures = driver.root.join(".work/check-36842-1793308072826242000");
    for (file, expected, limit) in [
        (
            "syft-context/candidate",
            "f677c74b9a6a3759508389bf5fd37f71cfdb960fec9d997cbc028e64ac600e92",
            128 * 1024 * 1024,
        ),
        (
            "syft-context/binary-metadata.txt",
            "ab144eb223e8745df1aeaa012384042ec6ba3339985aef16c6b2a62898124982",
            JSON_LIMIT,
        ),
        (
            "syft-context/module-graph.txt",
            "d6d95d5f84ac16fe82131052c778634ebf5ed749578efd0a7df1b10a314529fe",
            JSON_LIMIT,
        ),
        (
            "49-stdout.log",
            "788183773fbe66c930301a9954505a338006ae9749486849e89a635f5983f083",
            JSON_LIMIT,
        ),
    ] {
        assert_eq!(hash(&captures.join(file), limit)?, expected);
    }
    assert!(
        String::from_utf8(bytes(&captures.join("49-stdout.log"), JSON_LIMIT)?)
            .map_err(|_| "invalid captured test output")?
            .lines()
            .any(|line| line.starts_with("FAIL"))
    );
    let image = crate::built_image_id(&captures.join("syft-candidate.iid"))?;
    assert_eq!(
        image,
        "sha256:2c34a0fd21b681a2b053dba0f7ff04b505148cf7938b5b7ba4e39e2ff43dd9a1"
    );
    driver.inspect(&image, arch)?;
    let public = driver
        .root
        .join(".work/syft-dependency-captured-measurement");
    mkdir(&public, false)?;
    // Freshness-check the previous measurement's sealed read-only DB, rather
    // than retrying the interrupted cold-refresh operation or relaxing age.
    let cache = driver.root.join(".work/syft-native-candidate/cache");
    let status = scanner(
        &mut driver,
        GRYPE,
        &["db", "status", "--output", "json"],
        &[mount(&cache, "/cache", true)?],
        false,
        0,
    )?;
    let db = read_json(&status)?;
    db_status(&db, Utc::now())?;
    let (catalog, measured) =
        super::observe(&mut driver, &image, arch, "candidate", &public, &cache, &db)?;
    let modules = super::modules(&catalog, "go1.27.3")?;
    assert_eq!(
        modules
            .get("github.com/go-jose/go-jose/v4")
            .map(String::as_str),
        Some("v4.1.6")
    );
    assert_eq!(
        modules.get("golang.org/x/net").map(String::as_str),
        Some("v0.62.0")
    );
    let summary = json!({"schema":1,"status":"blocked-captured-binary-measurement","arch":arch,"created":Utc::now().to_rfc3339(),"compiler":super::COMPILER,"source_archive_sha256":super::SOURCE_HASH,"patch_sha256":super::PATCH_HASH,"go_mod_sha256":super::PATCHED_MOD,"go_sum_sha256":super::PATCHED_SUM,"candidate_binary_sha256":"f677c74b9a6a3759508389bf5fd37f71cfdb960fec9d997cbc028e64ac600e92","candidate":measured,"db":db,"upstream_race_tests":"failed-or-incomplete","original_full_run":"interrupted-during-db-refresh; residual-owned-scanner-removal-confirmed","compiler_input_catalog":"prior-output-limit-failure-unresolved","native_inventory_approved":false,"complete_notice_source_provenance_review":false,"release_accepted":false,"scope":"fresh offline scan of retained bytes; no rebuild, test rerun, approval or substitution for interrupted full run"});
    write_json(&public.join("summary.json"), &summary)
}
