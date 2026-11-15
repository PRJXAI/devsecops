# Synthetic upstream OS-image fixtures

These are actual Docker-save archives built offline from the three scratch-only
contexts in [Syft's pinned source](https://github.com/anchore/syft/tree/a0c0d3890a9d79421c403e8fcadec50a2e55bf21/internal/os/testdata).
They contain only the upstream synthetic os-release/content-manifest inputs.
They supplement the public fixture-cache OCI artifact, which omits these cases.
The original upstream tests and their expected results are unchanged.

The archives are parser test data, **not** native executable qualification,
scanner inventories, release handoffs or published service images. Their arm64
configuration is intentional input metadata; both native workers parse the same
non-executable data. No scanner/compiler container receives a Docker socket.

| File | SHA-256 |
| --- | --- |
| `not-rhel.tar` | `04afeaa7e5fba473488b1556ba895b2836d2d4aca3347c5e1cccc89885943335` |
| `rhel-manifests.tar` | `39a2ae2f09b8a557e90268ff7457a2bee9d9bf6979ffe6f9b028f6b111c6af0a` |
| `rhel-no-manifests.tar` | `befc70081e96a5b9b18f89b96ced88027936603de81158e91ae09fcf163a34c3` |

Source attribution and licensing remain the pinned upstream Apache-2.0 source.
The build recipes use only `FROM scratch` and `COPY` of those public inputs.
