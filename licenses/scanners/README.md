# Scanner licenses and source availability

The candidate Syft 1.57.1 and Grype 0.121.3 distributions are rebuilt from fixed upstream commits with reviewed dependency-manifest patches and Go 1.27.4. They are modified distributions, not unmodified upstream release binaries. Original terms remain in force; no upstream endorsement or relicensing is claimed.

## Included material

- `syft-NOTICES.txt`: prominent derivative/source/patch notice, then verbatim legal texts from **297** captured module source trees and **38** Go 1.27.4 legal files.
- `grype-NOTICES.txt`: equivalent material for **320** module source trees and the same compiler.
- `syft-index.json` / `grype-index.json`: native embedded versions, actual capture run/source, module checksums/origins and legal-file hashes/sizes. Main-module legal attribution uses the fixed upstream base only after native VCS verification; embedded dirty/pseudo-versions are not rewritten. The collection-time approval field remains false; collection alone never approves release.
- `STATIC-BASE-NOTICES.txt`: unchanged MPL-2.0, original IANA public-domain notice, MIT terms, source routes and original Wolfi baselayout source/control texts. Package `20230201-r31` / commit `ed415005c84750f03c4a9252137813734a224ae7` matches the native base metadata.

Images install tool notices at `/usr/share/licenses/TOOL/THIRD-PARTY-NOTICES.txt` and base notices at `/usr/share/licenses/static-base/NOTICES.txt`, mode 0444. Filesystem contracts require exact reviewed bytes; upstream root LICENSE files remain separate.

Collection includes named LICENSE/LICENCE/UNLICENSE, NOTICE, COPYING, PATENTS and copyright files. Test/example legal texts may also appear; inclusion does not assert compilation. Go source commit `7b2881024c95a11ddb86663a616340aa3a88b67f` is bound by Git blob identities, with original text retained.

## Index metadata erratum — 2026-11-15

The indexes at published source `7d20ea6ba4956a65db1640ec3752534d9dc4b727` incorrectly put each scanner's upstream commit in `go_source_commit`: a collector-local variable shadowed the already verified Go commit. The compiler texts, their Git-blob verification, this source documentation and `review.json` already identified Go `7b2881024c95a11ddb86663a616340aa3a88b67f` correctly. Both indexes and the collector now agree, with a hash/source/bundle consistency regression. No native catalog, notice payload, module attribution, compiler, accepted risk or released image bytes are changed by this metadata-only erratum. It does not relabel the earlier index field as correct or imply a new binary delivery.

## Obtain source

Each `MODULE@VERSION` in the index identifies public source. Retrieve it with `GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go mod download -json MODULE@VERSION`, verify the recorded `h1:` checksum and inspect its source directory. Recorded public origins/commits and these source routes preserve recipients' rights, including file-level copyleft source access.

Main bases: [Syft](https://github.com/anchore/syft/tree/a0c0d3890a9d79421c403e8fcadec50a2e55bf21), [Grype](https://github.com/anchore/grype/tree/cd1f23eb50dfb52647090158f453c7359172591f). Compiler/library source: [Go 1.27.4](https://github.com/golang/go/tree/7b2881024c95a11ddb86663a616340aa3a88b67f). The exact image source-revision tree contains `images/{syft,grype}/Dockerfile` and `patches/*-security.patch.txt`, binding archives and modified dependency manifests. The native replacement `github.com/sbomify/ar` is attributed to its actual fork source and fixed commit, not the abandoned original module.

The unmodified CA PEM bundle is editable certificate source data at `/etc/ssl/certs/ca-certificates.crt`, under its declared MPL-2.0/MIT terms. IANA data is public domain. Original baselayout source/control files are included in the base notice; the [complete source package](https://apk.cgr.dev/chainguard/aarch64/wolfi-baselayout-source-20230201-r31.apk) hashes to `902fc22a76f11e1a5a0cf9960196c91137fa5ece6d1bafca8126f3ff2b1bbabe`.

This records source/notice arrangements, not legal certification, independent reproducible-build proof or supplier trust guarantees. Native qualification, artifact-specific redistribution review and manual publication remain separate gates. [Risk acceptance](../../docs/security.md) is unchanged and does not transfer to these derivatives. Other tools, especially Git/native Gitleaks, retain separate source obligations and are not approved here.
