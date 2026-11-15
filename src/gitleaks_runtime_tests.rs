use super::*;
use sha2::Digest;

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
