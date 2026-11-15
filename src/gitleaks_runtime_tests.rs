use super::*;
use sha2::Digest;

#[test]
fn current_material_review_binds_original_sources_without_granting_a_release() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let review = read_json(&root.join("licenses/gitleaks-current-review.json")).unwrap();
    assert_eq!(
        review["review"]["publication_from_this_record_alone_authorized"],
        false
    );
    assert_eq!(
        review["review"]["fresh_both_native_release_preparations_required"],
        true
    );
    assert_eq!(
        review["review"]["independent_vendor_reproducibility_established"],
        false
    );
    assert_eq!(
        review["native_material"]["native_notice_sha256"],
        hash(
            &root.join("licenses/gitleaks-runtime-NOTICES.txt"),
            1024 * 1024
        )
        .unwrap()
    );
    assert_eq!(
        review["native_material"]["source_index_sha256"],
        hash(
            &root.join("licenses/gitleaks-runtime-source-index.json"),
            1024 * 1024
        )
        .unwrap()
    );
    let current = read_json(&root.join("licenses/gitleaks-runtime-source-index.json")).unwrap();
    assert_eq!(current["redistribution_approved"], false);
    let rows = current["native_source_observations"]["observations"]
        .as_array()
        .unwrap();
    assert_eq!(rows.len(), 20);
    for arch in ["amd64", "arm64"] {
        let names: std::collections::BTreeSet<_> = rows
            .iter()
            .filter(|row| row["arch"] == arch)
            .map(|row| row["package"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), 10);
        for source in sources(arch).unwrap() {
            let observation = rows
                .iter()
                .find(|row| {
                    row["arch"] == arch && row["source_file"] == format!("{arch}/{}", source.name)
                })
                .unwrap();
            assert_eq!(observation["source_apk_sha256"], source.sha256);
            assert!(observation["source_manifest_files"].as_u64().unwrap() > 0);
            assert_eq!(observation["signature_verified"], false);
        }
    }
    let go =
        read_json(&root.join("licenses/gitleaks-go-notices/current-source-index.json")).unwrap();
    assert_eq!(go["redistribution_approved"], false);
    assert_eq!(
        review["go_material"]["compiler_source_commit"],
        go["go_source_commit"]
    );
    assert_eq!(
        review["go_material"]["source_index_sha256"],
        hash(
            &root.join("licenses/gitleaks-go-notices/current-source-index.json"),
            1024 * 1024
        )
        .unwrap()
    );
}

#[test]
fn source_delivery_requires_every_original_byte_mode_and_member_without_extracting() {
    let driver = Driver::new().unwrap();
    let file = driver.logs.join("synthetic-source.tar");
    let name = "usr/share/licenses/gitleaks/corresponding-source/test-source.apk";
    let original = b"synthetic unit bytes; never a native source archive or scan input";
    let digest: String = sha2::Sha256::digest(original)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let expected = vec![(name.into(), digest, original.len() as u64)];
    for case in [
        "valid",
        "missing",
        "changed",
        "mode",
        "duplicate",
        "link",
        "foreign",
    ] {
        let mut archive = tar::Builder::new(Vec::new());
        if case != "missing" {
            let data = if case == "changed" {
                &b"changed"[..]
            } else {
                &original[..]
            };
            let mut header = tar::Header::new_gnu();
            header.set_size(if case == "link" { 0 } else { data.len() as u64 });
            header.set_mode(if case == "mode" { 0o644 } else { 0o444 });
            if case == "link" {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_link_name("/outside").unwrap();
            }
            header.set_cksum();
            archive
                .append_data(
                    &mut header,
                    name,
                    if case == "link" { &b""[..] } else { data },
                )
                .unwrap();
            if case == "duplicate" || case == "foreign" {
                archive
                    .append_data(
                        &mut header,
                        if case == "foreign" {
                            "usr/share/licenses/gitleaks/corresponding-source/foreign.apk"
                        } else {
                            name
                        },
                        data,
                    )
                    .unwrap();
            }
        }
        fs::write(&file, archive.into_inner().unwrap()).unwrap();
        assert_eq!(
            verify_files(&file, &expected).is_ok(),
            case == "valid",
            "{case}"
        );
    }
    assert!(sources("foreign").is_err());
    for arch in ["amd64", "arm64"] {
        assert_eq!(sources(arch).unwrap().len(), 4);
    }
}
