#![forbid(unsafe_code)]
//! Structural checks only; native image execution and security review are separate.

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, path::Path};

    fn root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }
    fn sha256(text: &str) {
        let hash = text.split_whitespace().next().unwrap();
        assert_eq!(hash.len(), 64, "expected literal SHA-256");
        assert!(
            hash.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }
    #[test]
    fn dockerfiles_pin_artifacts_and_distroless_nonroot_finals() {
        let mut count = 0;
        for entry in fs::read_dir(root().join("images")).unwrap() {
            let path = entry.unwrap().path().join("Dockerfile");
            let text = fs::read_to_string(path).unwrap();
            let mut stages = BTreeSet::new();
            for line in text.lines().map(str::trim) {
                if let Some(syntax) = line.strip_prefix("# syntax=") {
                    sha256(syntax.split_once("@sha256:").unwrap().1);
                }
                if let Some(from) = line.strip_prefix("FROM ") {
                    let fields: Vec<_> = from.split_whitespace().collect();
                    let image = fields.iter().find(|v| !v.starts_with("--")).unwrap();
                    if let Some((_, hash)) = image.split_once("@sha256:") {
                        sha256(hash);
                    } else if *image != "scratch" {
                        for arch in ["amd64", "arm64"] {
                            assert!(
                                stages.contains(&image.replace("${TARGETARCH}", arch)),
                                "unpinned source: {image}"
                            );
                        }
                    }
                    if let Some(as_index) = fields.iter().position(|v| v.eq_ignore_ascii_case("AS"))
                    {
                        stages.insert(fields[as_index + 1].to_string());
                    }
                }
                if line.starts_with("ADD ") && line.contains("https://") {
                    sha256(line.split_once("--checksum=sha256:").unwrap().1);
                }
            }
            let final_stage = text.rsplit_once("\nFROM ").unwrap().1;
            assert!(
                final_stage.starts_with("cgr.dev/chainguard/static:")
                    || final_stage.starts_with("cgr.dev/chainguard/glibc-dynamic:")
            );
            assert!(final_stage.contains("USER 65532:65532"));
            assert!(final_stage.contains("ENTRYPOINT [\"/"));
            assert!(!final_stage.lines().any(|line| line.starts_with("RUN ")));
            assert!(!final_stage.contains("COPY . "));
            count += 1;
        }
        assert_eq!(count, 9, "review inventory when adding/removing tools");
    }
    fn cargo_launcher(command: &str) -> bool {
        command.starts_with("cargo ")
            && ![";", "|", "&&", "$(", "`", "<<"]
                .iter()
                .any(|v| command.contains(v))
    }
    fn direct_extraction(command: &str) -> bool {
        let Some((options, args)) = command.split_once('[') else {
            return false;
        };
        options.split_whitespace().all(|v| v.starts_with("--"))
            && (args.starts_with("\"mkdir\",") || args.starts_with("\"tar\","))
    }
    #[test]
    fn rust_is_the_only_glue_layer() {
        let workflow = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
        for line in workflow.lines().map(str::trim) {
            if let Some(command) = line
                .strip_prefix("- run:")
                .or_else(|| line.strip_prefix("run:"))
            {
                assert!(cargo_launcher(command.trim()), "CI must launch Rust only");
            }
        }
        fn walk(path: &Path) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let kind = entry.file_type().unwrap();
                assert!(!kind.is_symlink(), "no symlinked glue inputs");
                if kind.is_dir() {
                    walk(&path);
                } else {
                    let extension = path.extension().and_then(|v| v.to_str()).unwrap_or("");
                    assert!(
                        !["py", "sh", "bash", "js", "mjs", "cjs", "ts", "ps1"].contains(&extension),
                        "first-party glue must be Rust"
                    );
                    if path.file_name().unwrap() == "Dockerfile" {
                        for line in fs::read_to_string(&path).unwrap().lines().map(str::trim) {
                            if let Some(command) = line.strip_prefix("RUN ") {
                                assert!(
                                    direct_extraction(command),
                                    "Docker RUN must be direct exec-form extraction"
                                );
                            }
                        }
                    }
                }
            }
        }
        for folder in ["images", "src", ".github", ".agents"] {
            walk(&root().join(folder));
        }
    }
    #[test]
    fn glue_policy_rejects_inline_scripts_and_shell_disguises() {
        for command in [
            "python -c x",
            "node -e x",
            "|",
            "cargo test && docker build .",
            "cargo test; python x",
            "cargo run $(python x)",
            "cargo test `node x`",
        ] {
            assert!(!cargo_launcher(command));
        }
        for command in [
            "echo x",
            "--network=none sh -c x",
            "[\"sh\", \"-c\", \"tar x\"]",
            "--network=none echo x [\"tar\", \"x\"]",
        ] {
            assert!(!direct_extraction(command));
        }
        assert!(cargo_launcher(
            "cargo run --locked --bin devsecops -- check syft"
        ));
        assert!(direct_extraction(
            "--network=none [\"tar\", \"-xzf\", \"/tmp/tool.tgz\"]"
        ));
    }
    #[test]
    fn publication_permissions_and_external_actions_are_scoped() {
        let workflow = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
        let (build, publish) = workflow.split_once("  publish:\n").unwrap();
        assert!(!build.contains("packages: write") && !build.contains("id-token: write"));
        assert!(!workflow.contains("pull_request_target:") && !workflow.contains("workflow_run:"));
        for required in [
            "github.event_name == 'workflow_dispatch'",
            "github.ref == 'refs/heads/main'",
            "inputs.publish",
            "inputs.redistribution_reviewed",
            "needs: [structure, images]",
            "DEVSECOPS_LICENSE_SOURCE_PROVENANCE_APPROVED_SHA: ${{ github.sha }}",
            "subject-checksums: .work/published/subjects.checksums",
        ] {
            assert!(publish.contains(required));
        }
        assert!(
            !workflow.contains(".work/scans/"),
            "raw reports must not be uploaded"
        );
        for line in workflow.lines().map(str::trim) {
            if let Some(action) = line
                .strip_prefix("- uses: ")
                .or_else(|| line.strip_prefix("uses: "))
            {
                let (_, revision) = action.split_once('@').unwrap();
                assert_eq!(revision.len(), 40);
                assert!(revision.bytes().all(|b| b.is_ascii_hexdigit()));
            }
        }
    }
    #[test]
    fn build_context_is_deny_by_default() {
        let rules = fs::read_to_string(root().join(".dockerignore")).unwrap();
        assert_eq!(rules.lines().next(), Some("**"));
        for required in [".git", ".work", "target", "**/.env", "**/credentials*"] {
            assert!(rules.lines().any(|line| line == required));
        }
    }
    #[test]
    fn documentation_links_resolve() {
        fn check(path: &Path) {
            let text = fs::read_to_string(path).unwrap();
            for part in text.split("](").skip(1) {
                let target = part.split(')').next().unwrap().split('#').next().unwrap();
                if !target.is_empty() && !target.contains("://") {
                    assert!(
                        path.parent().unwrap().join(target).exists(),
                        "broken link in {}: {target}",
                        path.display()
                    );
                }
            }
        }
        for file in [
            "AGENTS.md",
            "README.md",
            "docs/tool-inventory.md",
            "docs/results.md",
            ".agents/skills/maintain-tool-images/SKILL.md",
            ".agents/skills/verify-tool-images/SKILL.md",
            ".agents/skills/maintain-docs/SKILL.md",
            "licenses/README.md",
        ] {
            check(&root().join(file));
        }
    }
}
