//! Fixed current native-material assembly proposal; not publication approval.
use crate::{
    Result,
    release::{bytes, hash, mkdir, read_json, write_json, write_new},
};
use serde_json::json;
use std::path::Path;

#[test]
#[ignore = "fixed reviewed source observation and original native legal files; proposal only"]
fn assemble_current_gitleaks_native_notices() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let input = root.join(".work/gitleaks-native-legal");
    let observation_file = input.join("source-observation.json");
    let observation_hash = "dea1d687cb664ca4b00455b856d7bfa4273faea8917ef2d1684d0858f85d7513";
    if hash(&observation_file, 1024 * 1024)? != observation_hash {
        return Err("changed native source observations");
    }
    let observations = read_json(&observation_file)?;
    if observations["observations"]
        .as_array()
        .is_none_or(|rows| rows.len() != 20)
        || observations["redistribution_approved"] != false
    {
        return Err("source observations are not approval");
    }
    let output = root.join(".work/gitleaks-native-notice-proposal");
    mkdir(&output, false)?;
    let mut bundle = b"Gitleaks native runtime material and recipients' rights.\n\nModified distribution rebuilt by PRJXAI from the exact source/patch/recipe tree identified by org.opencontainers.image.revision at https://github.com/PRJXAI/devsecops . No upstream endorsement or relicensing is claimed. Go/compiler material is in GO-NOTICES.txt; this document covers retained Git/GNU libraries, PCRE2/SLJIT, zlib and base data.\n\nGit 2.56.1-r1, glibc 2.44-r19 (including loader/POSIX locale), GCC runtime libraries 16.2.0-r4 and Wolfi baselayout 20230201-r31 have complete corresponding-source companion APKs. Their upstream sources, vendor overlays, build recipes and source checksums accompany the selected architecture under /usr/share/licenses/gitleaks/corresponding-source/. SOURCE-INDEX.json identifies exact source archives and native package/file observations. These source archives are data, not executable runtime dependencies. Verify SHA-256 before opening; on a separate administrative system inspect with gzip -dc FILE.apk | tar -tf - --ignore-zeros and read the included usr/src/ORIGIN/SOURCES.sha256. Full preferred-form source and original terms remain available, not a future written source offer.\n\nThe sources and dynamic library arrangements preserve recipients' upstream rights to modify/replace/relink the GNU libraries. There is no vendor signature lock or additional license restriction: recipients may rebuild the public Docker recipe with their modified libraries. Read-only/container containment is an execution control, not a restriction on those rights. No independent vendor reproducibility or standalone APK signature authentication is asserted; trust is the HTTPS supplier, pinned source/archive hashes and selected native payload identity.\n\nPCRE2 10.49-r3 is the actual libpcre2-8-0 subpackage from source commit 6f9d7c1373262c541324a16a358785b33ef116cf, including SLJIT gitlink de0259c7aaf36aa40cba8014f3fad3edde9307f9. zlib source is 767c4c947852e143f582c85f14cf573411df1b35. Their original permissive notices follow. The unavailable exact PCRE2/zlib source-companion URLs are not presented as available or as a GPL corresponding-source claim. Native byte matches and vendor recipe source coordinates are retained in the index.\n\nCA 20261020-r0 is unmodified editable PEM certificate source data delivered at /etc/ssl/certs/ca-certificates.crt under MPL-2.0/MIT, without added rights restrictions. The original reviewed base-data material below also includes optional IANA text; inclusion does not assert that every named file is retained in this runtime.\n\nOriginal legal terms/copyrights follow unchanged. This document alone is not a binary release, complete native qualification or redistribution approval receipt.\n".to_vec();
    let mut records = Vec::new();
    for (file, expected, source) in [
        (
            "GIT-COPYING.txt",
            "5b2198d1645f767585e8a88ac0499b04472164c0d2da22e75ecf97ef443ab32e",
            "Git v2.56.1 / COPYING; same bytes as fixed runtime license",
        ),
        (
            "current-glibc-COPYING.LESSERv2.txt",
            "20e50fe7aae3e56378ebf0417d9de904f55a0e61e4df315333e632a4d3555d95",
            "Exact glibc source companion / upstream git438677ef498552b28c2060060c9e3947373f1e2c / COPYING.LESSERv2; COPYING.LIB is its symlink",
        ),
        (
            "current-glibc-COPYINGv2.txt",
            "edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6",
            "Exact glibc source companion / upstream git438677ef498552b28c2060060c9e3947373f1e2c / COPYINGv2",
        ),
        (
            "current-glibc-COPYINGv3.txt",
            "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
            "Exact glibc source companion / upstream git438677ef498552b28c2060060c9e3947373f1e2c / COPYINGv3",
        ),
        (
            "current-glibc-LICENSES.txt",
            "b22a69aa3f80a5201818c66cb0df0f25f9fa13cf5861b0093a058dbd12d50dce",
            "Exact glibc source companion / upstream git438677ef498552b28c2060060c9e3947373f1e2c / LICENSES; failed public mirror route not used",
        ),
        (
            "current-gcc-COPYING3.txt",
            "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903",
            "GCC source git78d4ac73dd391005b895a6148cd9831e28e1208b / COPYING3",
        ),
        (
            "current-gcc-COPYING.RUNTIME.txt",
            "9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74",
            "GCC source git78d4ac73dd391005b895a6148cd9831e28e1208b / COPYING.RUNTIME",
        ),
        (
            "PCRE2-LICENCE.md",
            "197d8a73ffee0d6b09adba2f9c677b5f5aede24edf89258a68e48248d010d811",
            "PCRE2 source6f9d7c1373262c541324a16a358785b33ef116cf / LICENCE.md",
        ),
        (
            "PCRE2-COPYING.txt",
            "99272c55f3dcfa07a8a7e15a5c1a33096e4727de74241d65fa049fccfdd59507",
            "PCRE2 source6f9d7c1373262c541324a16a358785b33ef116cf / COPYING",
        ),
        (
            "PCRE2-AUTHORS.md",
            "412ace3355a4d6a4d835c350a7df172903811eafda7b13500dacf58429ee757e",
            "PCRE2 source6f9d7c1373262c541324a16a358785b33ef116cf / AUTHORS.md",
        ),
        (
            "SLJIT-LICENSE.txt",
            "5f216505c0f6ea3273caec89e766eef93cdeb7bbb0c429f9360116d7c938feeb",
            "PCRE2 SLJIT gitlink de0259c7aaf36aa40cba8014f3fad3edde9307f9 / LICENSE",
        ),
        (
            "ZLIB-LICENSE.txt",
            "e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2",
            "zlib source767c4c947852e143f582c85f14cf573411df1b35 / LICENSE",
        ),
        (
            "ZLIB-README.txt",
            "717b18319152b2682049a3cafb9c17d30128cdc800f92442ef1b91fb4787f615",
            "zlib source767c4c947852e143f582c85f14cf573411df1b35 / README",
        ),
    ] {
        let path = input.join(file);
        if hash(&path, 1024 * 1024)? != expected {
            return Err("changed original native legal text");
        }
        let data = bytes(&path, 1024 * 1024)?;
        bundle.extend_from_slice(format!("\n--- {source} ---\n").as_bytes());
        bundle.extend_from_slice(&data);
        records.push(json!({"source":source,"sha256":expected,"bytes":data.len()}));
    }
    let base = root.join("licenses/scanners/STATIC-BASE-NOTICES.txt");
    let base_hash = "378fef9d3e685a2ad1168283453781a01a66bd8ccc7e261e490340712bf18af4";
    if hash(&base, 1024 * 1024)? != base_hash {
        return Err("changed original base legal material");
    }
    let data = bytes(&base, 1024 * 1024)?;
    bundle.extend_from_slice(b"\n--- Original reviewed MPL/MIT/base source material (optional source notices included) ---\n");
    bundle.extend_from_slice(&data);
    records.push(json!({"source":"original reviewed static base legal/source material","sha256":base_hash,"bytes":data.len()}));
    if bundle.len() > 1024 * 1024 {
        return Err("native notice budget exceeded");
    }
    let file = output.join("NATIVE-NOTICES.txt");
    write_new(&file, &bundle, 0o444)?;
    write_json(
        &output.join("source-index.json"),
        &json!({"schema":1,"source_capture_run":43753305153u64,"source_capture_sha":"8f3e46e8f4919a106ef0040b5daf1502fc5c20d2","observation_sha256":observation_hash,"native_source_observations":observations,"original_legal_files":records,"native_notice_sha256":hash(&file,1024*1024)?,"native_notice_bytes":bundle.len(),"source_archive_delivery":"required; not yet verified in built image","redistribution_approved":false}),
    )
}
