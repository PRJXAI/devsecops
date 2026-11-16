# Current Gitleaks Go/compiler notice material

The fixed Rust collection uses both unchanged native catalogs from run [43753305153](https://github.com/PRJXAI/devsecops/actions/runs/43753305153), actual source merge tree `8f3e46e8f4919a106ef0040b5daf1502fc5c20d2` and native Go **1.27.4**. It includes **91 original legal texts from all 63 non-stdlib native module trees**, plus **38 original Go compiler/library legal texts**. The aggregate is **366,906 bytes**, including prominent modified-distribution/source/patch disclosures and source headings. Original legal bytes are unchanged; source trees can contain optional/test material not compiled into the executable.

[index.json](index.json) binds the exact packaged aggregate and [current-source-index.json](current-source-index.json). The latter records every module, dependency source checksum/origin and original file hash/size. Ordinary checks verify every original file inside the packaged aggregate and compare its complete module set against the unchanged native production profile. The exact reviewed Go 1.27.4 material is reused byte-for-byte from the hash-bound scanner collection; its compiler source is `7b2881024c95a11ddb86663a616340aa3a88b67f`, not a scanner upstream commit.

## Main source discrepancy, not a guessed tag mapping

The binary's native main label remains **v8.30.1**. Its actual fixed source is Gitleaks commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`, archive SHA-256 `6b2638a733b85619dc80bdf28e84e4fed7e526a761ab5c148fbf67695aea2115`. The immutable Go proxy `v8.30.1` record instead identifies `8d1f98c7967eb1e79cb44ac6241a124e145d2165`; the reason for this discrepancy is not independently established. The first attempted attribution failed and is retained. Main legal material is therefore taken from the **exact build archive**, with its root LICENSE additionally checked against the runtime recipe. No native version, origin or report is rewritten to make the tag appear consistent. Other modules retain public proxy/checksum-database verification, with no private/VCS fallback.

## Packaging is not redistribution approval

Packaging preserves the aggregate at `/usr/share/licenses/gitleaks/GO-NOTICES.txt`, with an assembly/source heading and exact byte/mode checks. The older Go 1.27.3 collection remains in Git history and preserved evidence, not current packaging. One exact legal-file Git attribute preserves upstream whitespace; wildcard/driver/code exemptions remain rejected.

Collection approval remains **false**. Native Git/glibc/GCC source/notice/recipient arrangements, permissive runtime attribution, fresh full dual-native release gates and artifact-specific review remain separate requirements. This does not establish independent reproducibility or approve publication. No Gitleaks image has been published by this work.
