#![forbid(unsafe_code)]
//! Structural checks only; native image execution and security review are separate.

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        path::{Component, Path, PathBuf},
        process::Command,
    };

    fn root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }
    const TOOLS: [&str; 9] = [
        "cargo-audit",
        "cargo-deny",
        "docker",
        "gitleaks",
        "grype",
        "kind",
        "kubectl",
        "kustomize",
        "syft",
    ];

    fn sha256(hash: &str) -> bool {
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }

    fn pinned_image(image: &str) -> bool {
        image.split_once("@sha256:").is_some_and(|(name, hash)| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._-:".contains(&b))
                && sha256(hash)
        })
    }

    fn absolute_path(path: &str, directory: bool) -> bool {
        let Some(rest) = path.strip_prefix('/') else {
            return false;
        };
        let rest = if directory {
            rest.trim_end_matches('/')
        } else {
            rest
        };
        !rest.is_empty()
            && rest.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
    }

    fn remote_add(args: &str) -> bool {
        let fields: Vec<_> = args.split_whitespace().collect();
        let mut checksum = false;
        let mut mode = false;
        let mut index = 0;
        while let Some(option) = fields.get(index).filter(|v| v.starts_with("--")) {
            if let Some(hash) = option.strip_prefix("--checksum=sha256:") {
                if checksum || !sha256(hash) {
                    return false;
                }
                checksum = true;
            } else if matches!(*option, "--chmod=0444" | "--chmod=0555" | "--chmod=0644") {
                if mode {
                    return false;
                }
                mode = true;
            } else {
                return false;
            }
            index += 1;
        }
        if !checksum || fields.len() != index + 2 || !absolute_path(fields[index + 1], true) {
            return false;
        }
        // No local ADD, Git/SSH URLs, HTTP, variable URLs or extra sources.
        fields[index].strip_prefix("https://").is_some_and(|url| {
            url.split_once('/').is_some_and(|(host, path)| {
                host.contains('.')
                    && !path.is_empty()
                    && host
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                    && path
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/._-%".contains(&b))
            })
        })
    }

    fn narrow_copy(args: &str, stages: &BTreeSet<String>, tool: &str) -> bool {
        let fields: Vec<_> = args.split_whitespace().collect();
        let mut flags = BTreeSet::new();
        let mut index = 0;
        while let Some(option) = fields.get(index).filter(|v| v.starts_with("--")) {
            let Some((key, value)) = option.split_once('=') else {
                return false;
            };
            if !flags.insert(key)
                || !match key {
                    "--from" => stages.contains(value),
                    "--chmod" => matches!(value, "0444" | "0555" | "0644"),
                    "--chown" => value == "65532:65532",
                    _ => false,
                }
            {
                return false;
            }
            index += 1;
        }
        // Only individually named supplier files, never a whole rootfs/context,
        // directory, glob, external image or alternate JSON COPY syntax.
        flags.contains("--from")
            && fields.len() >= index + 2
            && fields[index..fields.len() - 1].iter().all(|v| {
                absolute_path(v, false)
                    && (matches!(
                        *v,
                        "/syft"
                            | "/grype"
                            | "/kind"
                            | "/kubectl"
                            | "/LICENSE"
                            | "/kustomize.tar.gz"
                            | "/cargo-deny.tar.gz"
                            | "/cargo-audit.tgz"
                            | "/usr/bin/gitleaks"
                            | "/usr/bin/git"
                            | "/usr/lib/libpcre2-8.so.0"
                            | "/usr/lib/libz.so.1"
                            | "/usr/local/bin/docker"
                            | "/usr/local/libexec/docker/cli-plugins/docker-compose"
                            | "/usr/local/libexec/docker/cli-plugins/docker-buildx"
                            | "/out/kustomize"
                            | "/out/cargo-audit"
                            | "/out/cargo-deny"
                            | "/out/LICENSE-APACHE"
                            | "/out/LICENSE-MIT"
                            | "/out/README.md"
                            | "/out/CHANGELOG.md"
                    ) || tool == "cargo-audit"
                        && matches!(
                            *v,
                            "/usr/lib/ld-linux-x86-64.so.2"
                                | "/usr/lib/ld-linux-aarch64.so.1"
                                | "/usr/lib/libc.so.6"
                                | "/usr/lib/libm.so.6"
                                | "/usr/lib/libgcc_s.so.1"
                                | "/usr/lib/libpthread.so.0"
                                | "/usr/lib/libdl.so.2"
                        ))
            })
            && absolute_path(fields[fields.len() - 1], true)
    }

    fn official_audit_supplier(text: &str) -> bool {
        // Exact tool-specific stage graph, not a general inheritance exemption.
        // Both final bases and every copied ELF must retain their reviewed pins.
        let instructions: Vec<_> = text
            .lines()
            .filter_map(|line| {
                let (op, args) = line.trim().split_once(' ')?;
                let op = op.to_ascii_uppercase();
                matches!(op.as_str(), "FROM" | "ADD" | "COPY" | "RUN" | "LABEL")
                    .then(|| format!("{op} {args}"))
            })
            .collect();
        let static_base = "cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde";
        let expected = [
            "FROM scratch AS archive-amd64".into(),
            "ADD --checksum=sha256:1890badd5f15831a9af4b074399fcd21e6f7c0fe42c84e9254cdffc9f813765c https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.22.1/cargo-audit-x86_64-unknown-linux-gnu-v0.22.1.tgz /cargo-audit.tgz".into(),
            "FROM scratch AS archive-arm64".into(),
            "ADD --checksum=sha256:4c8df835ee484441bd2c8c6bcac28c4ce4b4058ba9e7477cb9e0012fe7769f66 https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.22.1/cargo-audit-aarch64-unknown-linux-gnu-v0.22.1.tgz /cargo-audit.tgz".into(),
            "FROM --platform=$BUILDPLATFORM alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 AS extract".into(),
            "RUN --network=none [\"mkdir\", \"/out\"]".into(),
            "FROM extract AS binary-amd64".into(),
            "COPY --from=archive-amd64 /cargo-audit.tgz /tmp/cargo-audit.tgz".into(),
            "RUN --network=none [\"tar\", \"-xzf\", \"/tmp/cargo-audit.tgz\", \"-C\", \"/out\", \"--strip-components=1\"]".into(),
            "FROM extract AS binary-arm64".into(),
            "COPY --from=archive-arm64 /cargo-audit.tgz /tmp/cargo-audit.tgz".into(),
            "RUN --network=none [\"tar\", \"-xzf\", \"/tmp/cargo-audit.tgz\", \"-C\", \"/out\", \"--strip-components=1\"]".into(),
            "FROM binary-${TARGETARCH} AS binary".into(),
            "FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:5380a8b913d0900cf44180e2205bf3ebf0e0b00a32a0f2fa4ab16cb06d7f9cdf AS glibc".into(),
            format!("FROM {static_base} AS runtime-amd64"),
            "COPY --from=glibc /usr/lib/ld-linux-x86-64.so.2 /usr/lib/ld-linux-x86-64.so.2".into(),
            "COPY --from=glibc /usr/lib/libc.so.6 /usr/lib/libm.so.6 /usr/lib/libgcc_s.so.1 /usr/lib/".into(),
            format!("FROM {static_base} AS runtime-arm64"),
            "COPY --from=glibc /usr/lib/ld-linux-aarch64.so.1 /usr/lib/ld-linux-aarch64.so.1".into(),
            "COPY --from=glibc /usr/lib/libc.so.6 /usr/lib/libm.so.6 /usr/lib/libgcc_s.so.1 /usr/lib/libpthread.so.0 /usr/lib/libdl.so.2 /usr/lib/".into(),
            "FROM runtime-${TARGETARCH}".into(),
            "LABEL org.opencontainers.image.title=\"cargo-audit\" org.opencontainers.image.version=\"0.22.1\" org.opencontainers.image.source=\"https://github.com/rustsec/rustsec\"".into(),
            "COPY --from=binary --chmod=0555 /out/cargo-audit /usr/local/bin/cargo-audit".into(),
            "COPY --from=binary-amd64 /out/LICENSE-APACHE /out/LICENSE-MIT /out/README.md /out/CHANGELOG.md /usr/share/licenses/cargo-audit/".into(),
        ];
        instructions == expected
    }

    fn docker_policy(text: &str, tool: &str) -> bool {
        let mut stages = BTreeSet::new();
        let mut final_image = String::new();
        let mut final_user = String::new();
        let mut final_entrypoint = Vec::<String>::new();
        let mut final_run = false;
        let mut pending = String::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(comment) = line.strip_prefix('#') {
                if let Some((key, value)) = comment.trim().split_once('=') {
                    if key.eq_ignore_ascii_case("syntax") {
                        if !pinned_image(value) {
                            return false;
                        }
                    } else if key.eq_ignore_ascii_case("escape")
                        || key.eq_ignore_ascii_case("check")
                    {
                        return false;
                    }
                }
                continue;
            }
            if line.contains(['\r', '\t']) {
                return false;
            }
            let continued = line.ends_with('\\');
            pending.push_str(line.strip_suffix('\\').unwrap_or(line));
            if continued {
                let instruction = pending.split_whitespace().next().unwrap_or("");
                if !instruction.eq_ignore_ascii_case("ENV")
                    && !instruction.eq_ignore_ascii_case("LABEL")
                {
                    return false;
                }
                pending.push(' ');
                continue;
            }
            let Some((instruction, args)) = pending.split_once(char::is_whitespace) else {
                return false;
            };
            let args = args.trim();
            if args.is_empty() || args.contains(['\\', '\r', '\n']) {
                return false;
            }
            match instruction.to_ascii_uppercase().as_str() {
                "FROM" => {
                    let mut fields: Vec<_> = args.split_whitespace().collect();
                    if fields.first() == Some(&"--platform=$BUILDPLATFORM") {
                        fields.remove(0);
                    }
                    if fields.len() != 1
                        && !(fields.len() == 3 && fields[1].eq_ignore_ascii_case("AS"))
                    {
                        return false;
                    }
                    let image = fields[0];
                    if image != "scratch"
                        && !pinned_image(image)
                        && !["amd64", "arm64"]
                            .iter()
                            .all(|arch| stages.contains(&image.replace("${TARGETARCH}", arch)))
                    {
                        return false;
                    }
                    if fields.len() == 3 {
                        let alias = fields[2];
                        if alias.is_empty()
                            || !alias
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                            || !stages.insert(alias.to_string())
                        {
                            return false;
                        }
                    }
                    final_image = image.to_string();
                    final_user.clear();
                    final_entrypoint.clear();
                    final_run = false;
                }
                "ADD" => {
                    if final_image.is_empty() || !remote_add(args) {
                        return false;
                    }
                }
                "COPY" => {
                    if final_image.is_empty() || !narrow_copy(args, &stages, tool) {
                        return false;
                    }
                }
                "RUN" => {
                    if final_image.is_empty() || !direct_extraction(args) {
                        return false;
                    }
                    final_run = true;
                }
                "USER" => {
                    if final_image.is_empty() {
                        return false;
                    }
                    final_user = args.to_string();
                }
                "ENTRYPOINT" => {
                    if final_image.is_empty() {
                        return false;
                    }
                    let Ok(values) = serde_json::from_str::<Vec<String>>(args) else {
                        return false;
                    };
                    final_entrypoint = values;
                }
                "CMD" => {
                    if final_image.is_empty()
                        || !matches!(tool, "cargo-audit" | "cargo-deny" | "docker")
                        || serde_json::from_str::<Vec<String>>(args).ok().as_deref()
                            != Some(&["--help".into()])
                    {
                        return false;
                    }
                }
                "WORKDIR" => {
                    if final_image.is_empty() || !absolute_path(args, true) {
                        return false;
                    }
                }
                "ENV" | "LABEL" => {
                    if final_image.is_empty() || !args.contains('=') {
                        return false;
                    }
                }
                _ => return false,
            }
            pending.clear();
        }
        let mut expected = vec![format!("/usr/local/bin/{tool}")];
        if tool == "cargo-audit" {
            expected.push("audit".into());
        }
        pending.is_empty()
            && TOOLS.contains(&tool)
            && (if tool == "cargo-audit" {
                final_image == "runtime-${TARGETARCH}" && official_audit_supplier(text)
            } else {
                pinned_image(&final_image)
                    && (final_image.starts_with("cgr.dev/chainguard/static:")
                        || final_image.starts_with("cgr.dev/chainguard/glibc-dynamic:"))
            })
            && !final_run
            && final_user == "65532:65532"
            && final_entrypoint == expected
    }

    #[test]
    fn dockerfiles_pin_artifacts_and_distroless_nonroot_finals() {
        let mut names = BTreeSet::new();
        for entry in fs::read_dir(root().join("images")).unwrap() {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_dir());
            let tool = entry.file_name().into_string().unwrap();
            let path = entry.path().join("Dockerfile");
            assert!(fs::symlink_metadata(&path).unwrap().is_file());
            let text = fs::read_to_string(&path).unwrap();
            assert!(docker_policy(&text, &tool), "{}", path.display());
            names.insert(tool);
        }
        assert_eq!(names, TOOLS.map(String::from).into_iter().collect());
    }
    fn cargo_launcher(command: &str) -> bool {
        // An allowlist, not a shell parser: even single &, redirects, expansions,
        // quotes, escapes and line breaks must never reach the runner's shell.
        matches!(
            command,
            "cargo fmt --all -- --check"
                | "cargo clippy --all-targets --locked -- -D warnings"
                | "cargo test --locked"
                | "cargo test --locked --bin devsecops release::gitleaks_candidate::native_gitleaks_dependency_candidate -- --ignored --exact"
                | "cargo run --locked --bin devsecops -- audit-dependencies"
                | "cargo run --locked --bin devsecops -- catalog-candidates"
                | "cargo run --locked --bin devsecops -- prepare-release"
                | "cargo run --locked --bin devsecops -- publish-all"
        ) || TOOLS
            .iter()
            .any(|tool| command == format!("cargo run --locked --bin devsecops -- check {tool}"))
    }
    fn direct_extraction(command: &str) -> bool {
        let Some(json) = command.strip_prefix("--network=none ") else {
            return false;
        };
        let Ok(args) = serde_json::from_str::<Vec<String>>(json) else {
            return false;
        };
        if args == ["mkdir", "/out"] {
            return true;
        }
        if args.len() < 5 || args[..2] != ["tar", "-xzf"] || args[3..5] != ["-C", "/out"] {
            return false;
        }
        let archive = &args[2];
        archive.starts_with("/tmp/")
            && absolute_path(archive, false)
            && (archive.ends_with(".tgz") || archive.ends_with(".tar.gz"))
            && matches!(
                args[5..]
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .as_slice(),
                [] | ["--strip-components=1"] | ["kustomize"]
            )
    }
    fn git_command(folder: &Path) -> Command {
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(folder)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_COUNT", "0");
        for key in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
        ] {
            command.env_remove(key);
        }
        command
    }

    fn eligible_files(folder: &Path) -> Vec<PathBuf> {
        // Git, not recursive read_dir: include root/new directories and untracked
        // eligible files, without opening ignored .work/target/operator contents.
        let output = git_command(folder)
            .args([
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot enumerate first-party files"
        );
        output
            .stdout
            .split(|b| *b == 0)
            .filter(|v| !v.is_empty())
            .map(|v| PathBuf::from(std::str::from_utf8(v).unwrap()))
            .collect()
    }

    fn rust_glue_file(folder: &Path, relative: &Path) -> bool {
        let mut path = folder.to_path_buf();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return false;
            };
            let name_text = name.to_string_lossy();
            if [".git", ".work", "target", "node_modules"]
                .iter()
                .any(|v| name == *v)
                || name_text == ".env"
                || name_text.starts_with(".env.")
                || name_text.starts_with("credentials")
            {
                return false;
            }
            path.push(name);
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                return false;
            };
            if metadata.file_type().is_symlink() {
                return false;
            }
        }
        let name = relative.file_name().and_then(|v| v.to_str()).unwrap_or("");
        let extension = relative
            .extension()
            .and_then(|v| v.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !["rs", "md", "toml", "lock", "json", "yml", "yaml", "txt"].contains(&extension.as_str())
            && ![
                "Dockerfile",
                ".dockerignore",
                ".gitignore",
                "LICENSE",
                "COPYING",
                "NOTICE",
            ]
            .contains(&name)
        {
            return false;
        }
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            return false;
        };
        if !metadata.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 != 0 && extension != "rs" {
                return false;
            }
        }
        let Ok(bytes) = fs::read(&path) else {
            return false;
        };
        // Also catch extension-disguised interpreter launchers, not Rust attributes.
        if bytes.starts_with(b"#!") && !bytes.starts_with(b"#![") {
            return false;
        }
        if relative == Path::new("tests/fixtures/gitleaks/Dockerfile") {
            return candidate_dockerfile(&bytes);
        }
        if name == "Dockerfile" {
            let Some(tool) = relative
                .parent()
                .and_then(Path::file_name)
                .and_then(|v| v.to_str())
            else {
                return false;
            };
            return std::str::from_utf8(&bytes).is_ok_and(|text| docker_policy(text, tool));
        }
        true
    }

    fn candidate_dockerfile(bytes: &[u8]) -> bool {
        use sha2::Digest;
        // One reviewed non-publishing fixture, not a new supplier/COPY/RUN policy.
        sha2::Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            == "b38eb1e0a20e9334e6e95d63eb357a42d25759bc80afaa14208129cb669d27de"
    }
    #[test]
    fn candidate_fixture_cannot_expand_the_production_build_policy() {
        let fixture = fs::read(root().join("tests/fixtures/gitleaks/Dockerfile")).unwrap();
        assert!(candidate_dockerfile(&fixture));
        let text = std::str::from_utf8(&fixture).unwrap();
        for (old, new) in [
            ("65532:65532", "0"),
            ("COPY --chmod=0555 candidate", "COPY --chmod=0555 ."),
            ("WORKDIR /tmp", "RUN [\"sh\",\"-c\",\"true\"]\nWORKDIR /tmp"),
        ] {
            assert!(!candidate_dockerfile(text.replace(old, new).as_bytes()));
        }
        assert!(!docker_policy(text, "gitleaks"));
        assert!(!cargo_launcher(
            "cargo test --locked --bin devsecops arbitrary -- --ignored --exact"
        ));
    }
    #[test]
    fn collected_go_notice_bytes_and_module_coverage_match_the_index() {
        use sha2::Digest;
        let folder = root().join("licenses/gitleaks-go-notices");
        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(folder.join("index.json")).unwrap()).unwrap();
        assert_eq!(index["redistribution_approved"], false);
        assert_eq!(index["embedded_go_modules"], 62);
        assert_eq!(index["modules_with_named_notice_files"], 62);
        assert_eq!(
            index["modules_without_named_notice_files"],
            serde_json::json!([])
        );
        let mut names = BTreeSet::new();
        let mut modules = BTreeSet::new();
        let mut total = 0u64;
        for record in index["files"].as_array().unwrap() {
            let file = record["file"].as_str().unwrap();
            assert!(
                file.starts_with("files/")
                    && file.ends_with(".txt")
                    && !file.contains("..")
                    && file.matches('/').count() == 1
            );
            let path = folder.join(file);
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata.is_file() && metadata.len() > 0 && metadata.len() <= 1024 * 1024);
            let bytes = fs::read(&path).unwrap();
            let hash = sha2::Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert_eq!(record["sha256"], hash);
            assert_eq!(record["bytes"], bytes.len());
            total += bytes.len() as u64;
            assert!(names.insert(file.to_owned()));
            if let Some(module) = record["module"].as_str() {
                assert!(record["go_source_sum"].as_str().unwrap().starts_with("h1:"));
                modules.insert(module.to_owned());
            }
        }
        let actual: BTreeSet<_> = fs::read_dir(folder.join("files"))
            .unwrap()
            .map(|entry| format!("files/{}", entry.unwrap().file_name().to_str().unwrap()))
            .collect();
        assert_eq!(names, actual);
        assert_eq!(names.len(), 95);
        assert_eq!(modules.len(), 62);
        assert_eq!(total, 294214);
        assert_eq!(index["total_bytes"], total);
    }
    #[test]
    fn candidate_identity_evidence_cannot_claim_scan_or_release_acceptance() {
        let evidence: serde_json::Value = serde_json::from_slice(
            &fs::read(root().join("inventory/gitleaks-candidate-evidence.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(evidence["release_accepted"], false);
        assert_eq!(evidence["vulnerability_scan"], "not-run");
        assert_eq!(evidence["architectures"].as_object().unwrap().len(), 2);
        for arch in ["amd64", "arm64"] {
            let entry = &evidence["architectures"][arch];
            assert_eq!(entry["exact_named_tuples"], 74);
            assert_eq!(entry["unknown_versions"], 0);
            for field in ["summary_sha256", "sbom_sha256", "reported_archive_sha256"] {
                assert!(sha256(entry[field].as_str().unwrap()));
            }
        }
    }
    #[test]
    fn rust_is_the_only_glue_layer() {
        for relative in eligible_files(root()) {
            assert!(
                rust_glue_file(root(), &relative),
                "unreviewed/non-Rust glue: {}",
                relative.display()
            );
        }
    }
    #[test]
    fn docker_policy_rejects_adversarial_mutations() {
        for tool in TOOLS {
            let text =
                fs::read_to_string(root().join(format!("images/{tool}/Dockerfile"))).unwrap();
            // Docker instruction names are case-insensitive, their operands aren't.
            let lowercase = text
                .lines()
                .map(|line| {
                    if let Some((instruction, args)) = line.split_once(' ')
                        && instruction.bytes().all(|b| b.is_ascii_uppercase())
                    {
                        return format!("{} {args}", instruction.to_ascii_lowercase());
                    }
                    line.to_string()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(docker_policy(&lowercase, tool), "lowercase {tool}");
            for extra in [
                "user 0",
                "UsEr root",
                "entrypoint [\"/bin/sh\"]",
                "ENTRYPOINT /bin/sh",
                "entrypoint [\"/usr/local/bin/other\"]",
                "run --network=none [\"mkdir\", \"/out\"]",
                "copy --from=unknown / /",
                "COPY . /workspace",
                "ONBUILD RUN sh -c x",
                "FROM scratch",
                "cmd [\"sh\", \"-c\", \"x\"]",
            ] {
                assert!(
                    !docker_policy(&format!("{text}\n{extra}\n"), tool),
                    "{tool}: {extra}"
                );
            }
            assert!(!docker_policy(
                &text.replace("USER 65532:65532", "# USER 65532:65532"),
                tool
            ));
            assert!(docker_policy(
                &format!("{text}\nUSER 0\nuser 65532:65532\n"),
                tool
            ));
        }
        let text = fs::read_to_string(root().join("images/syft/Dockerfile")).unwrap();
        for source in [
            "/", "/.", "/./", "/*", ".", "/rootfs", "/usr", "/syft/", "/../syft",
        ] {
            let changed = text.replace(
                "COPY --from=supplier /syft",
                &format!("copy --from=supplier {source}"),
            );
            assert!(
                !docker_policy(&changed, "syft"),
                "rootfs/context copy: {source}"
            );
        }
        for source in [
            "http://example.org/tool",
            "git://example.org/tool",
            "git@example.org:tool",
            "https://example.org/${TOOL}",
            "local.tgz",
        ] {
            let checksum = "a".repeat(64);
            assert!(!remote_add(&format!(
                "--checksum=sha256:{checksum} {source} /tool"
            )));
        }
        for args in [
            "https://example.org/tool /tool",
            "--checksum=sha256:${HASH} https://example.org/tool /tool",
            "--checksum=sha256:abc https://example.org/tool /tool",
            "--checksum=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --keep-git-dir https://example.org/tool /tool",
            "[\"https://example.org/tool\", \"/tool\"]",
        ] {
            assert!(!remote_add(args), "unsafe ADD: {args}");
        }
        let hash = "a".repeat(64);
        let duplicate = format!(
            "--checksum=sha256:{hash} --checksum=sha256:{hash} https://example.org/tool /tool"
        );
        assert!(!remote_add(&duplicate));
        let bad_add = "add http://example.org/tool /tool\n";
        assert!(!docker_policy(&format!("{text}\n{bad_add}"), "syft"));
        assert!(!docker_policy(&text.replace("FROM anchore/syft:v1.55.0-nonroot@sha256:ec5bdbc745485920c6f444239f0c09ed87b3c4c165ff9433f95bc66b3500fbf9", "from anchore/syft:latest"), "syft"));
        assert!(!docker_policy(
            &format!("# syntax=docker/dockerfile:latest\n{text}"),
            "syft"
        ));
        assert!(!docker_policy(&format!("# escape=`\n{text}"), "syft"));
    }

    #[test]
    fn official_audit_supplier_and_minimal_closure_reject_substitution() {
        let text = fs::read_to_string(root().join("images/cargo-audit/Dockerfile")).unwrap();
        assert!(docker_policy(&text, "cargo-audit"));
        for (old, new) in [
            (
                "https://github.com/rustsec/rustsec/releases/download/",
                "https://github.com/cargo-bins/cargo-quickinstall/releases/download/",
            ),
            ("unknown-linux-gnu", "unknown-linux-musl"),
            (
                "4c8df835ee484441bd2c8c6bcac28c4ce4b4058ba9e7477cb9e0012fe7769f66",
                "1890badd5f15831a9af4b074399fcd21e6f7c0fe42c84e9254cdffc9f813765c",
            ),
            (
                "5380a8b913d0900cf44180e2205bf3ebf0e0b00a32a0f2fa4ab16cb06d7f9cdf",
                "17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde",
            ),
            ("AS runtime-arm64", "AS unreviewed-arm64"),
            ("FROM runtime-${TARGETARCH}", "FROM glibc"),
            (
                "COPY --from=binary --chmod=0555",
                "COPY --from=binary-amd64 --chmod=0555",
            ),
            ("COPY --from=archive-arm64", "COPY --from=archive-amd64"),
            ("/usr/lib/libpthread.so.0 /usr/lib/libdl.so.2 ", ""),
            ("/usr/lib/libgcc_s.so.1 ", ""),
            ("/usr/lib/libm.so.6 ", "/usr/lib/libstdc++.so.6 "),
            ("/out/LICENSE-APACHE ", ""),
            ("--strip-components=1", "strip-components=1"),
        ] {
            assert!(text.contains(old), "ineffective mutation: {old}");
            assert!(
                !docker_policy(&text.replace(old, new), "cargo-audit"),
                "accepted: {new}"
            );
        }
        let extra = text.replace(
            "FROM runtime-${TARGETARCH}",
            "FROM runtime-${TARGETARCH}\nCOPY --from=glibc /usr/lib/libc.so.6 /usr/local/bin/extra",
        );
        assert!(!docker_policy(&extra, "cargo-audit"));
    }

    #[test]
    fn extraction_rejects_network_and_executable_options() {
        for command in [
            "--network=host [\"tar\", \"-xzf\", \"/tmp/a.tgz\", \"-C\", \"/out\"]",
            "--network=none --mount=type=ssh [\"mkdir\", \"/out\"]",
            "--security=insecure --network=none [\"mkdir\", \"/out\"]",
            "[\"mkdir\", \"/out\"]",
            "--network=none [\"mkdir\", \"-p\", \"/out\"]",
            "--network=none [\"tar\", \"-xzf\", \"/tmp/a.tgz\", \"-C\", \"/\"]",
            "--network=none [\"tar\", \"-xzf\", \"/tmp/a.tgz\", \"-C\", \"/out\", \"--checkpoint-action=exec=sh\"]",
            "--network=none [\"tar\", \"-xzf\", \"/tmp/a.tgz\", \"-C\", \"/out\", \"--to-command=sh\"]",
            "--network=none [\"tar\", \"-xzf\", \"/tmp/a.tgz\", \"-C\", \"/out\", \"--use-compress-program=sh\"]",
            "--network=none [\"tar\", \"-I\", \"sh\", \"-xf\", \"/tmp/a.tgz\", \"-C\", \"/out\"]",
            "--network=none [\"tar\", \"-xzf\", \"/tmp/../a.tgz\", \"-C\", \"/out\"]",
            "--network=none [\"tar\", \"-xzf\", \"https://example.org/a.tgz\", \"-C\", \"/out\"]",
            "--network=none [\"mkdir\", \"/out\"] && sh -c x",
            "--network=none [\"mkdir\", \"/out\", 1]",
        ] {
            assert!(!direct_extraction(command), "unsafe extraction: {command}");
        }
        for tail in ["", ", \"--strip-components=1\"", ", \"kustomize\""] {
            assert!(direct_extraction(&format!(
                "--network=none [\"tar\", \"-xzf\", \"/tmp/a.tgz\", \"-C\", \"/out\"{tail}]"
            )));
        }
        let text = fs::read_to_string(root().join("images/kustomize/Dockerfile")).unwrap();
        assert!(!docker_policy(
            &text.replace("RUN --network=none", "run --network=host"),
            "kustomize"
        ));
        assert!(!docker_policy(
            &text.replace("\"kustomize\"]", "\"--to-command=sh\"]"),
            "kustomize"
        ));
    }

    #[test]
    fn license_only_stages_can_be_inlined_without_weakening_pins() {
        for tool in ["kind", "kubectl", "kustomize"] {
            let text =
                fs::read_to_string(root().join(format!("images/{tool}/Dockerfile"))).unwrap();
            // Positive S1 compatibility fixture, without changing any Dockerfile.
            let Some((_, after)) = text.split_once("FROM scratch AS notices\n") else {
                assert!(docker_policy(&text, tool));
                continue;
            };
            let add = after.lines().next().unwrap();
            assert!(add.starts_with("ADD ") && add.ends_with(" /LICENSE"));
            let inlined = text
                .replace(&format!("FROM scratch AS notices\n{add}\n"), "")
                .replace(
                    &format!("COPY --from=notices /LICENSE /usr/share/licenses/{tool}/LICENSE"),
                    &format!(
                        "{} /usr/share/licenses/{tool}/LICENSE",
                        add.strip_suffix(" /LICENSE").unwrap()
                    ),
                );
            assert!(docker_policy(&inlined, tool));
            assert!(!docker_policy(
                &inlined.replace("--checksum=sha256:", "--unsupported=sha256:"),
                tool
            ));
        }
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let name = format!(
                "devsecops-checks-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            );
            let path = std::env::temp_dir().join(name);
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn git_eligible_root_and_new_directory_glue_is_checked_without_ignored_data() {
        let scratch = Scratch::new();
        assert!(
            git_command(&scratch.0)
                .args(["init", "--quiet"])
                .output()
                .unwrap()
                .status
                .success()
        );
        fs::write(
            scratch.0.join(".gitignore"),
            "/.work/\n/target/\n/operator/\n",
        )
        .unwrap();
        for dir in [".work", "target", "operator", "new-directory"] {
            fs::create_dir(scratch.0.join(dir)).unwrap();
        }
        for file in [".work/private.py", "target/build.sh", "operator/local.js"] {
            fs::write(scratch.0.join(file), "ignored synthetic data").unwrap();
        }
        fs::write(scratch.0.join("checks.rs"), "#![forbid(unsafe_code)]\n").unwrap();
        fs::write(scratch.0.join("new-directory/task.rs"), "fn main() {}\n").unwrap();
        for file in [
            "root.py",
            "root.sh",
            "root.js",
            "new-directory/task.ts",
            "new-directory/task.go",
            "new-directory/task.PS1",
            "new-directory/launcher.md",
        ] {
            fs::write(scratch.0.join(file), "#!/usr/bin/env interpreter\n").unwrap();
        }
        let eligible = eligible_files(&scratch.0);
        assert_eq!(eligible.len(), 10);
        for file in &eligible {
            let allowed = matches!(
                file.to_str().unwrap(),
                ".gitignore" | "checks.rs" | "new-directory/task.rs"
            );
            assert_eq!(
                rust_glue_file(&scratch.0, file),
                allowed,
                "{}",
                file.display()
            );
        }
        assert!(!eligible.iter().any(|p| p.starts_with(".work")
            || p.starts_with("target")
            || p.starts_with("operator")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            symlink(
                "../.work/private.py",
                scratch.0.join("new-directory/link.rs"),
            )
            .unwrap();
            assert!(!rust_glue_file(
                &scratch.0,
                Path::new("new-directory/link.rs")
            ));
            let disguised = scratch.0.join("new-directory/launcher.txt");
            fs::write(&disguised, "interpreter data\n").unwrap();
            fs::set_permissions(disguised, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(!rust_glue_file(
                &scratch.0,
                Path::new("new-directory/launcher.txt")
            ));
        }
    }

    #[test]
    fn glue_policy_rejects_inline_scripts_and_shell_disguises() {
        for command in [
            "cargo test --locked & other-command",
            "cargo test --locked\ncargo audit",
            "cargo test --locked\rnode x",
            "cargo test --locked >output",
            "cargo test --locked <input",
            "cargo test --locked ${COMMAND}",
            "cargo test --locked \\\nnode x",
            "cargo test --locked # comment",
            "cargo test --locked || node x",
            "cargo test --locked &",
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
            "--network=none [\"tar\", \"-xzf\", \"/tmp/tool.tgz\", \"-C\", \"/out\"]"
        ));
    }
    // Deliberately support only this reviewed CI layout. These are policy fixtures,
    // not YAML generation: alternate scalar/block/anchor/merge syntax needs review.
    // Preserve indentation so the dispatch input can never be mistaken for a job.
    const WORKFLOW_HEADER: &str = "\
name: distroless-images
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '17 7 * * 1'
  workflow_dispatch:
    inputs:
      publish:
        description: Publish clean images to GHCR from main
        type: boolean
        default: false
      redistribution_reviewed:
        description: Confirm tool/dependency notices, Git corresponding source and supplier provenance have been reviewed
        type: boolean
        default: false
permissions:
  contents: read
concurrency:
  group: images-${{ github.ref }}
  cancel-in-progress: false
jobs:";
    const STRUCTURE_JOB: &str = "  structure:
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@PIN
        with: {persist-credentials: false}
      - run: cargo fmt --all -- --check
      - run: cargo clippy --all-targets --locked -- -D warnings
      - run: cargo test --locked
      - run: cargo run --locked --bin devsecops -- audit-dependencies
      - name: Public dependency count/status summary only
        if: always()
        uses: actions/upload-artifact@PIN
        with:
          name: dependency-security-status
          path: .work/public-audit.json
          retention-days: 14
          if-no-files-found: error";
    const IMAGES_JOB: &str = "  images:
    needs: structure
    strategy:
      fail-fast: false
      matrix:
        include:
          - runner: ubuntu-24.04
            arch: amd64
          - runner: ubuntu-24.04-arm
            arch: arm64
    runs-on: ${{ matrix.runner }}
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@PIN
        with: {persist-credentials: false}
      - name: Capture public native inventories for review, not release acceptance
        run: cargo run --locked --bin devsecops -- catalog-candidates
      - name: Preserve native inventory evidence, including blocked profiles
        if: always()
        uses: actions/upload-artifact@PIN
        with:
          name: catalog-evidence-${{ matrix.arch }}
          path: .work/catalog-evidence/
          retention-days: 14
          if-no-files-found: error
      - name: Rust builds, smokes, inventories and scans the exact native images
        run: cargo run --locked --bin devsecops -- prepare-release
      - name: Public count/status summary only
        if: always()
        uses: actions/upload-artifact@PIN
        with:
          name: security-status-${{ matrix.arch }}
          path: .work/public-release/summary.json
          retention-days: 14
          if-no-files-found: error
      - name: Validate experimental Gitleaks natively without release approval
        if: always()
        run: cargo test --locked --bin devsecops release::gitleaks_candidate::native_gitleaks_dependency_candidate -- --ignored --exact
      - name: Preserve experimental native inventory and status only
        if: always()
        uses: actions/upload-artifact@PIN
        with:
          name: gitleaks-native-candidate-${{ matrix.arch }}
          path: .work/gitleaks-native-candidate/
          retention-days: 14
          if-no-files-found: error
      - name: Preserve only clean archives, inventories and bound receipts
        uses: actions/upload-artifact@PIN
        with:
          name: release-${{ matrix.arch }}
          path: .work/release/
          retention-days: 1
          compression-level: 0
          include-hidden-files: true
          if-no-files-found: error";
    const PUBLISH_JOB: &str = "  publish:
    needs: [structure, images]
    if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && inputs.publish && inputs.redistribution_reviewed
    runs-on: ubuntu-24.04
    timeout-minutes: 40
    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@PIN
        with: {persist-credentials: false}
      - uses: actions/download-artifact@PIN
        with:
          pattern: release-*
          path: .work/downloaded
      - uses: docker/login-action@PIN
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - name: Verify both architectures and publish exact scanned bytes, never rebuild
        env:
          DEVSECOPS_PUBLISH_APPROVED: 'true'
          DEVSECOPS_LICENSE_SOURCE_PROVENANCE_APPROVED_SHA: ${{ github.sha }}
        run: cargo run --locked --bin devsecops -- publish-all
      - name: Attest all published manifest digests through GitHub
        uses: actions/attest-build-provenance@PIN
        with:
          subject-checksums: .work/published/subjects.checksums
      - uses: actions/upload-artifact@PIN
        with:
          name: published-digests
          path: .work/published/
          if-no-files-found: error";

    fn workflow_policy(text: &str) -> bool {
        let mut lines = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            if line.contains(['\t', '\r', '#']) || line.trim_end() != line {
                return false;
            }
            let value = line.trim_start();
            if let Some(command) = value
                .strip_prefix("- run: ")
                .or_else(|| value.strip_prefix("run: "))
                && !cargo_launcher(command)
            {
                return false;
            }
            if let Some(action) = value
                .strip_prefix("- uses: ")
                .or_else(|| value.strip_prefix("uses: "))
            {
                let Some((_, revision)) = action.split_once('@') else {
                    return false;
                };
                if revision.len() != 40 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return false;
                }
                lines.push(format!("{}@PIN", line.split_once('@').unwrap().0));
            } else {
                lines.push(line.to_string());
            }
        }
        let Some(jobs) = lines.iter().position(|line| line == "jobs:") else {
            return false;
        };
        if lines[..=jobs].join("\n") != WORKFLOW_HEADER {
            return false;
        }
        let bodies = &lines[jobs + 1..];
        let boundaries: Vec<_> = bodies
            .iter()
            .enumerate()
            .filter(|(_, line)| line.starts_with("  ") && !line.starts_with("   "))
            .map(|(index, _)| index)
            .chain(std::iter::once(bodies.len()))
            .collect();
        boundaries.len() == 4
            && boundaries[0] == 0
            && boundaries
                .windows(2)
                .zip([STRUCTURE_JOB, IMAGES_JOB, PUBLISH_JOB])
                .all(|(range, expected)| bodies[range[0]..range[1]].join("\n") == expected)
    }

    fn workflow_inventory(names: &[String]) -> bool {
        names == ["ci.yml"]
    }

    #[test]
    fn publication_permissions_and_external_actions_are_scoped() {
        let folder = root().join(".github/workflows");
        let mut names = Vec::new();
        for entry in fs::read_dir(folder).unwrap() {
            let entry = entry.unwrap();
            assert!(
                entry.file_type().unwrap().is_file(),
                "no workflow indirection"
            );
            names.push(entry.file_name().into_string().unwrap());
            assert!(workflow_policy(&fs::read_to_string(entry.path()).unwrap()));
        }
        assert!(workflow_inventory(&names), "unreviewed workflow inventory");
    }

    #[test]
    fn workflow_policy_rejects_adversarial_mutations() {
        let workflow = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
        assert!(workflow_policy(&workflow));
        for (old, new) in [
            (
                "  structure:\n",
                "  structure:\n    permissions: {packages: write}\n",
            ),
            (
                "  images:\n",
                "  images:\n    permissions:\n      id-token: write\n",
            ),
            (
                "  contents: read\nconcurrency:",
                "  contents: read\n  packages: write\nconcurrency:",
            ),
            (
                "github.event_name == 'workflow_dispatch'",
                "github.event_name == 'push'",
            ),
            (
                "github.ref == 'refs/heads/main'",
                "github.ref == 'refs/heads/dev'",
            ),
            (" && inputs.publish", " || inputs.publish"),
            (" && inputs.redistribution_reviewed", ""),
            ("    needs: [structure, images]", "    needs: structure"),
            (
                "          DEVSECOPS_PUBLISH_APPROVED: 'true'",
                "          # DEVSECOPS_PUBLISH_APPROVED: 'true'",
            ),
            (
                "          DEVSECOPS_LICENSE_SOURCE_PROVENANCE_APPROVED_SHA: ${{ github.sha }}",
                "          # DEVSECOPS_LICENSE_SOURCE_PROVENANCE_APPROVED_SHA: ${{ github.sha }}",
            ),
            (
                "APPROVED_SHA: ${{ github.sha }}",
                "APPROVED_SHA: ${{ github.event.before }}",
            ),
            (
                "subject-checksums: .work/published/subjects.checksums",
                "subject-checksums: .work/other",
            ),
            (
                "        run: cargo run --locked --bin devsecops -- publish-all",
                "        # run: cargo run --locked --bin devsecops -- publish-all",
            ),
            ("cargo test --locked", "cargo test --locked & node x"),
            (
                "cargo test --locked",
                "|\n          cargo test --locked\n          node x",
            ),
            (
                "cargo test --locked",
                "cargo test --locked\n        run: cargo audit",
            ),
            (
                "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
                "actions/checkout@main",
            ),
            ("  publish:\n    needs:", "  extra:\n    needs:"),
            (
                "    permissions:\n      contents: read",
                "    permissions: &privileged\n      contents: read",
            ),
        ] {
            assert!(workflow.contains(old), "ineffective mutation: {old}");
            assert!(
                !workflow_policy(&workflow.replace(old, new)),
                "accepted: {new}"
            );
        }
        for job in ["structure", "images"] {
            for permission in ["packages", "id-token"] {
                let old = format!("  {job}:\n");
                let new = format!("{old}    permissions:\n      {permission}: write\n");
                assert!(!workflow_policy(&workflow.replace(&old, &new)));
            }
        }
        for line in workflow.lines() {
            let value = line.trim_start();
            if let Some(action) = value
                .strip_prefix("- uses: ")
                .or_else(|| value.strip_prefix("uses: "))
            {
                let name = action.split_once('@').unwrap().0;
                assert!(!workflow_policy(
                    &workflow.replace(action, &format!("{name}@main"))
                ));
            }
            if value.starts_with("if: github.event_name") || value.starts_with("subject-checksums:")
            {
                let commented = format!("{}# {value}", " ".repeat(line.len() - value.len()));
                assert!(!workflow_policy(&workflow.replace(line, &commented)));
            }
        }
        let approval =
            "          DEVSECOPS_LICENSE_SOURCE_PROVENANCE_APPROVED_SHA: ${{ github.sha }}";
        let misplaced = workflow.replace(approval, "").replace(
            "  structure:\n",
            &format!("  structure:\n    env:\n{approval}\n"),
        );
        assert!(!workflow_policy(&misplaced));
        assert!(!workflow_inventory(&["ci.yml".into(), "extra.yml".into()]));
        assert!(!workflow_inventory(&["ci.yaml".into()]));
        assert!(!workflow_policy(&format!(
            "{workflow}\n  bypass:\n    uses: owner/repo@main\n"
        )));
        assert!(workflow_policy(&format!("# harmless comment\n{workflow}")));
    }
    fn context_policy(text: &str) -> bool {
        // Order is security-sensitive. Do not approximate Docker's glob engine:
        // permit exactly the reviewed minimal inclusions, then terminal denials.
        let rules: Vec<_> = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        rules
            == [
                "**",
                "!images/",
                "!images/*/",
                "!images/*/Dockerfile",
                "!licenses/",
                "!licenses/**",
                ".git",
                ".work",
                "target",
                "**/.env",
                "**/.env.*",
                "**/credentials*",
            ]
    }

    #[test]
    fn build_context_is_deny_by_default() {
        let rules = fs::read_to_string(root().join(".dockerignore")).unwrap();
        assert!(context_policy(&rules));
        for reinclusion in [
            "!.work",
            "!.work/**",
            "!target/",
            "!**/.env",
            "!**/credentials*",
            "!**",
            "!images/*/secret.sh",
        ] {
            assert!(!context_policy(&format!("{rules}\n{reinclusion}\n")));
        }
        for denial in [
            ".git",
            ".work",
            "target",
            "**/.env",
            "**/.env.*",
            "**/credentials*",
        ] {
            assert!(!context_policy(&rules.replace(denial, "")));
        }
        assert!(!context_policy(&rules.replacen("**\n", "*\n", 1)));
        assert!(!context_policy(&rules.replacen("!licenses/**", "!**", 1)));
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
            "docs/cargo-audit-supplier.md",
            ".agents/skills/maintain-tool-images/SKILL.md",
            ".agents/skills/verify-tool-images/SKILL.md",
            ".agents/skills/maintain-docs/SKILL.md",
            "licenses/README.md",
        ] {
            check(&root().join(file));
        }
    }
}
