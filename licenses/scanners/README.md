# Scanner licenses and source availability

The Syft/Grype images copy unmodified released executables from the literal supplier image digests in their Dockerfiles. These binaries retain their upstream licenses. This repository does not relicense them.

## Included material

- `syft-NOTICES.txt`: verbatim named legal texts from the **295** captured module source trees and **38** Go 1.26.8 legal files, with source headings.
- `grype-NOTICES.txt`: the equivalent material for **319** module source trees and the same Go version.
- `syft-index.json` / `grype-index.json`: module/version, Go checksum, source origin/commit where supplied and individual legal-file hash/size. The indexes' false approval field describes collection time; the later review is separate.
- `STATIC-BASE-NOTICES.txt`: MPL-2.0 text, IANA's original public-domain notice, MIT terms, source availability and the original Wolfi baselayout source/control texts. The source package identifies `20230201-r31` / commit `ed415005c84750f03c4a9252137813734a224ae7`, matching the captured package metadata. A source-package request without redirect handling initially captured no bytes; only the separately hashed followed response supplies this material.

The images place tool notices at `/usr/share/licenses/TOOL/THIRD-PARTY-NOTICES.txt` and base notices/source data at `/usr/share/licenses/static-base/NOTICES.txt`, mode 0444. Filesystem contracts verify exact bytes. Root upstream LICENSE files remain separately included.

Collection covers legal files in each named source tree, including `LICENCE`, `UNLICENSE`, NOTICE, COPYING, PATENTS and copyright files. Some trees contain test/example legal texts: their inclusion does not claim those files were compiled. The Go source version is pinned to commit `c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e`; legal files were checked against Git blob identities and retained without alteration.

## Obtain source

Every Go module is identified as `MODULE@VERSION` in the index and bundle. Retrieve its original source with `GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go mod download -json MODULE@VERSION`; verify the recorded `h1:` checksum and inspect the returned source directory. Public origins/commits are also recorded. This supplies the source route for file-level copyleft dependencies as well as permissive modules; recipients' source rights are not restricted by this packaging.

Go standard-library source: [Go go1.26.8](https://github.com/golang/go/tree/c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e). Main tool sources: [Syft](https://github.com/anchore/syft/tree/f15c3343e29dfb20cf6d82c820e7090b49808c96) and [Grype](https://github.com/anchore/grype/tree/afe2742527d98d822da06c9f32eed86fe3d193e0).

The unmodified CA PEM bundle is editable certificate source data delivered at `/etc/ssl/certs/ca-certificates.crt`, under the declared MPL-2.0/MIT terms. Its upstream source route is recorded in the static-base notice. IANA data is public domain as stated in its original notice. Original baselayout source/control files are included directly in the notice; the [complete source package](https://apk.cgr.dev/chainguard/aarch64/wolfi-baselayout-source-20230201-r31.apk) hashes to `902fc22a76f11e1a5a0cf9960196c91137fa5ece6d1bafca8126f3ff2b1bbabe`.

These are source/notice arrangements and a review of the selected unmodified suppliers, not independently reproduced builds, certification or a warranty that a supplier is benign. Risk acceptance is a separate [security decision](../../docs/security.md). Other tools, especially Git/native Gitleaks, have different source obligations and are not approved by this bundle.
