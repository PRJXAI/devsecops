# Synthetic upstream package-image fixture

`image-simple.tar` is an actual Docker-save archive built offline from
[Grype's pinned scratch-only context](https://github.com/anchore/grype/tree/cd1f23eb50dfb52647090158f453c7359172591f/grype/pkg/testdata/image-simple).
It contains only the upstream two synthetic package.json inputs. The original
package-exclusion tests and their expected results are unchanged.

SHA-256: `4e9f1960620315490f6c64057657fdd1355e1de9e76814cc27deb50d75b19203`.

This is parser data, not a native executable qualification, scanner inventory,
release handoff or published service image. Both native workers parse the same
arm64-configured non-executable data. No scanner/compiler gets a Docker socket.
Source attribution and licensing remain the upstream Apache-2.0 source.
