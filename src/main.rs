#![forbid(unsafe_code)]

mod release;

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::OwnedFd,
        unix::{
            fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, &'static str>;
const POLL: Duration = Duration::from_millis(20);
const LOG_LIMIT: usize = 8 * 1024 * 1024;
const TOOLS: &[&str] = &[
    "syft",
    "grype",
    "gitleaks",
    "cargo-audit",
    "cargo-deny",
    "kind",
    "kustomize",
    "kubectl",
    "docker",
];

fn version_args(tool: &str) -> Result<&'static [&'static str]> {
    match tool {
        "syft" | "grype" | "gitleaks" | "kind" | "kustomize" => Ok(&["version"]),
        "cargo-audit" | "cargo-deny" | "docker" => Ok(&["--version"]),
        "kubectl" => Ok(&["version", "--client=true"]),
        _ => Err("unknown tool"),
    }
}

// Nonblocking sockets avoid reader threads that can outlive a timed-out command.
// Only a bounded chunk is drained per poll; files never exceed LOG_LIMIT each.
struct Log {
    reader: UnixStream,
    file: File,
    size: usize,
    eof: bool,
}

impl Log {
    fn new(path: &Path) -> Result<(Self, Stdio)> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| "cannot create private log")?;
        let (reader, writer) = UnixStream::pair().map_err(|_| "cannot capture output")?;
        reader
            .set_nonblocking(true)
            .map_err(|_| "cannot capture output")?;
        Ok((
            Self {
                reader,
                file,
                size: 0,
                eof: false,
            },
            Stdio::from(OwnedFd::from(writer)),
        ))
    }

    fn drain(&mut self) -> Result<()> {
        let mut buffer = [0; 8192];
        for _ in 0..16 {
            match self.reader.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => {
                    let retained = n.min(LOG_LIMIT - self.size);
                    self.file
                        .write_all(&buffer[..retained])
                        .map_err(|_| "cannot write private log")?;
                    self.size += retained;
                    if retained != n {
                        return Err("command output limit exceeded");
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("cannot capture output"),
            }
        }
        Ok(())
    }
}

fn reap_until(child: &mut Child, limit: Duration) {
    let start = Instant::now();
    while start.elapsed() < limit {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        thread::sleep(POLL);
    }
    let _ = child.kill();
}

fn terminate(child: &mut Child) {
    // std has no safe process-group signalling API. Invoke kill directly, never a shell.
    if let Ok(mut killer) = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{}", child.id())])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        reap_until(&mut killer, Duration::from_secs(2));
    }
    let _ = child.kill();
    reap_until(child, Duration::from_secs(2));
}

struct Driver {
    root: PathBuf,
    logs: PathBuf,
    cancelled: Arc<AtomicBool>,
    sequence: u32,
}

impl Driver {
    fn new() -> Result<Self> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let work = root.join(".work");
        match DirBuilder::new().mode(0o700).create(&work) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err("cannot create private work directory"),
        }
        let metadata = fs::symlink_metadata(&work).map_err(|_| "cannot inspect work directory")?;
        if !metadata.is_dir() {
            return Err("work directory must not be a symlink");
        }
        fs::set_permissions(&work, fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot secure work directory")?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock unavailable")?
            .as_nanos();
        let logs = work.join(format!("check-{}-{stamp}", std::process::id()));
        DirBuilder::new()
            .mode(0o700)
            .create(&logs)
            .map_err(|_| "cannot create private log directory")?;
        let cancelled = Arc::new(AtomicBool::new(false));
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            signal_hook::flag::register(signal, Arc::clone(&cancelled))
                .map_err(|_| "cannot install cancellation handler")?;
        }
        Ok(Self {
            root,
            logs,
            cancelled,
            sequence: 0,
        })
    }

    fn docker(&mut self, args: &[&str], seconds: u64, cleanup: bool) -> Result<PathBuf> {
        if !cleanup && self.cancelled.load(Ordering::Relaxed) {
            return Err("check cancelled");
        }
        self.sequence += 1;
        let stdout_path = self.logs.join(format!("{}-stdout.log", self.sequence));
        let (mut stdout, out) = Log::new(&stdout_path)?;
        let (mut stderr, err) = Log::new(&self.logs.join(format!("{}-stderr.log", self.sequence)))?;
        let mut child = Command::new("docker")
            .args(args)
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .process_group(0)
            .spawn()
            .map_err(|_| "cannot start Docker command")?;
        let start = Instant::now();
        let result = (|| {
            let mut status = None;
            loop {
                if !cleanup && self.cancelled.load(Ordering::Relaxed) {
                    return Err("check cancelled");
                }
                if start.elapsed() >= Duration::from_secs(seconds) {
                    return Err("Docker command timed out");
                }
                stdout.drain()?;
                stderr.drain()?;
                if status.is_none() {
                    status = child
                        .try_wait()
                        .map_err(|_| "cannot monitor Docker command")?;
                }
                if let Some(status) = status.filter(|_| stdout.eof && stderr.eof) {
                    return if status.success() {
                        Ok(())
                    } else {
                        Err("Docker command failed; private logs retained")
                    };
                }
                thread::sleep(POLL);
            }
        })();
        if result.is_err() {
            terminate(&mut child);
        }
        result.map(|()| stdout_path)
    }

    fn smoke(
        &mut self,
        image: &str,
        tool: &str,
        args: &[&str],
        entrypoint: Option<&str>,
    ) -> Result<()> {
        let run_id = self
            .logs
            .file_name()
            .ok_or("missing run identity")?
            .to_str()
            .ok_or("invalid run identity")?;
        let name = format!("devsecops-{tool}-{run_id}-{}", self.sequence);
        let mut run = vec![
            "run",
            "--pull=never",
            "--name",
            &name,
            "--network=none",
            "--read-only",
            "--user=65532:65532",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=1",
            "--ulimit",
            "nofile=256:256",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
            "--env",
            "HOME=/tmp",
            "--env",
            "XDG_CACHE_HOME=/tmp/cache",
        ];
        if let Some(entrypoint) = entrypoint {
            run.extend(["--entrypoint", entrypoint]);
        }
        run.push(image);
        run.extend_from_slice(args);
        let result = self.docker(&run, 30, false);
        // Ignore the cancellation latch for this bounded cleanup, including spawn failures.
        let cleanup = self.docker(&["rm", "--force", &name], 10, true);
        let output = match (result, cleanup) {
            (Err(_), Err(_)) => return Err("check failed and container cleanup was not confirmed"),
            (Err(error), Ok(_)) => return Err(error),
            (Ok(_), Err(_)) => return Err("container cleanup failed; private logs retained"),
            (Ok(path), Ok(_)) => path,
        };
        let expected = if entrypoint == Some("/usr/bin/git") {
            "2.56.0.1.g02cd7dbd28"
        } else {
            match (tool, args) {
                ("syft", _) => "1.55.0",
                ("grype", _) => "0.121.0",
                ("gitleaks", _) => "8.30.1",
                ("cargo-audit", _) => "0.22.1",
                ("cargo-deny", _) => "0.20.2",
                ("kind", _) => "0.33.0",
                ("kustomize", _) => "5.8.1",
                ("kubectl", _) => "1.37.0",
                ("docker", ["compose", "version"]) => "5.6.1",
                ("docker", ["buildx", "version"]) => "0.38.1",
                ("docker", _) => "29.9.2",
                _ => return Err("unknown version contract"),
            }
        };
        let output = fs::read_to_string(output).map_err(|_| "cannot read version output")?;
        if !output
            .split_whitespace()
            .any(|word| word.trim_start_matches('v').trim_end_matches(',') == expected)
        {
            return Err("unexpected tool version; review supplier and version metadata together");
        }
        if self.cancelled.load(Ordering::Relaxed) {
            return Err("check cancelled");
        }
        Ok(())
    }

    fn native(&mut self) -> Result<&'static str> {
        if let Some(host) = std::env::var_os("DOCKER_HOST")
            && !host
                .to_str()
                .is_some_and(|host| host.starts_with("unix:///"))
        {
            return Err("only a local Unix-socket Docker endpoint is allowed");
        }
        let context = self.docker(
            &[
                "context",
                "inspect",
                "--format",
                "{{.Endpoints.docker.Host}}",
            ],
            15,
            false,
        )?;
        if !fs::read_to_string(context)
            .map_err(|_| "cannot read Docker endpoint")?
            .trim()
            .starts_with("unix:///")
        {
            return Err("only a local Unix-socket Docker context is allowed");
        }
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            _ => return Err("unsupported native architecture"),
        };
        let info = self.docker(
            &["info", "--format", "{{.OSType}} {{.Architecture}}"],
            15,
            false,
        )?;
        let info = fs::read_to_string(info).map_err(|_| "cannot read Docker architecture")?;
        let native: Vec<_> = info.split_whitespace().collect();
        let aliases = match arch {
            "amd64" => ["amd64", "x86_64"],
            _ => ["arm64", "aarch64"],
        };
        if native.len() != 2 || native[0] != "linux" || !aliases.contains(&native[1]) {
            return Err("Docker daemon must use the native Linux architecture");
        }
        Ok(arch)
    }

    fn inspect(&mut self, image: &str, arch: &str) -> Result<String> {
        let path = self.docker(&["image", "inspect", "--format", "{{.Id}} {{.Config.User}} {{.Os}} {{.Architecture}} {{index .Config.Labels \"org.opencontainers.image.source\"}} {{index .Config.Labels \"org.opencontainers.image.revision\"}}", image], 30, false)?;
        let text = fs::read_to_string(path).map_err(|_| "cannot read image inspection")?;
        let fields: Vec<_> = text.split_whitespace().collect();
        if fields.len() != 6
            || fields[1..4] != ["65532:65532", "linux", arch]
            || fields[4] != "https://github.com/PRJXAI/devsecops"
            || fields[5] != std::env::var("GITHUB_SHA").unwrap_or_else(|_| "local".into())
            || !fields[0]
                .strip_prefix("sha256:")
                .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("image identity, user or architecture check failed");
        }
        Ok(fields[0].to_owned())
    }

    fn check(&mut self, tool: &str) -> Result<String> {
        let args = version_args(tool)?;
        let arch = self.native()?;
        let platform = format!("linux/{arch}");
        let iidfile = self
            .logs
            .join(format!("build-{tool}-{}.iid", self.sequence));
        let dockerfile = format!("images/{tool}/Dockerfile");
        let revision = std::env::var("GITHUB_SHA").unwrap_or_else(|_| "local".into());
        if revision != "local"
            && !(revision.len() == 40 && revision.bytes().all(|v| v.is_ascii_hexdigit()))
        {
            return Err("invalid source revision");
        }
        let revision_label = format!("org.opencontainers.image.revision={revision}");
        self.docker(
            &[
                "build",
                "--label",
                "org.opencontainers.image.source=https://github.com/PRJXAI/devsecops",
                "--label",
                &revision_label,
                "--platform",
                &platform,
                "--file",
                &dockerfile,
                "--iidfile",
                iidfile.to_str().ok_or("invalid build identity path")?,
                ".",
            ],
            1200,
            false,
        )?;
        let image = built_image_id(&iidfile)?;
        if self.inspect(&image, arch)? != image {
            return Err("built image identity mismatch");
        }
        // Carry this immutable build identity through smoke, export and scanning.
        self.smoke(&image, tool, args, None)?;
        if tool == "gitleaks" {
            self.smoke(&image, tool, &["--version"], Some("/usr/bin/git"))?;
        }
        if tool == "docker" {
            self.smoke(&image, tool, &["compose", "version"], None)?;
            self.smoke(&image, tool, &["buildx", "version"], None)?;
        }
        Ok(image)
    }
}

fn built_image_id(path: &Path) -> Result<String> {
    let bytes = release::bytes(path, 128)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "invalid build identity")?
        .trim();
    if !text.strip_prefix("sha256:").is_some_and(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }) {
        return Err("invalid build identity");
    }
    Ok(text.to_owned())
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.as_slice() == ["prepare-release"] || args.as_slice() == ["publish-all"] {
        let result = Driver::new().and_then(|mut driver| {
            if args[0] == "prepare-release" {
                release::prepare(&mut driver)
            } else {
                release::publish(&mut driver)
            }
        });
        if let Err(error) = result {
            eprintln!("release task failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    let tools = match args.as_slice() {
        [command] if command == "check-all" => TOOLS.to_vec(),
        [command, tool] if command == "check" => {
            match tool.to_str().filter(|tool| version_args(tool).is_ok()) {
                Some(tool) => vec![tool],
                None => {
                    eprintln!("unknown tool");
                    std::process::exit(2);
                }
            }
        }
        _ => {
            eprintln!("usage: devsecops check TOOL | check-all");
            std::process::exit(2);
        }
    };
    let result = Driver::new().and_then(|mut driver| {
        for tool in tools {
            driver.check(tool)?;
            println!("{tool}: native image user/architecture and offline version smoke passed (not release acceptance)");
        }
        Ok(())
    });
    if let Err(error) = result {
        eprintln!("check failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{TOOLS, version_args};

    #[test]
    fn explicit_tool_versions() {
        assert_eq!(TOOLS.len(), 9);
        for tool in TOOLS {
            assert!(version_args(tool).is_ok());
        }
        for tool in ["syft", "grype", "gitleaks", "kind", "kustomize"] {
            assert_eq!(version_args(tool).unwrap(), ["version"]);
        }
        for tool in ["cargo-audit", "cargo-deny", "docker"] {
            assert_eq!(version_args(tool).unwrap(), ["--version"]);
        }
        assert_eq!(
            version_args("kubectl").unwrap(),
            ["version", "--client=true"]
        );
    }

    #[test]
    fn build_identity_is_private_bounded_and_independent_of_tags() {
        let driver = super::Driver::new().unwrap();
        let first = driver.logs.join("first.iid");
        let second = driver.logs.join("second.iid");
        let a = format!("sha256:{}", "a".repeat(64));
        let b = format!("sha256:{}", "b".repeat(64));
        std::fs::write(&first, &a).unwrap();
        std::fs::write(&second, &b).unwrap();
        assert_eq!(super::built_image_id(&first).unwrap(), a);
        assert_eq!(super::built_image_id(&second).unwrap(), b);
        for bad in [
            "".to_owned(),
            "sha256:short".into(),
            format!("{a}\n{b}"),
            "x".repeat(129),
        ] {
            std::fs::write(&first, bad).unwrap();
            assert!(super::built_image_id(&first).is_err());
        }
        assert!(super::built_image_id(&driver.logs.join("missing")).is_err());
        let link = driver.logs.join("linked.iid");
        std::os::unix::fs::symlink(&second, &link).unwrap();
        assert!(super::built_image_id(&link).is_err());
    }

    #[test]
    fn rejects_unknown_tools_and_argument_injection() {
        for tool in [
            "",
            "git",
            "../syft",
            "SYFT",
            "syft;id",
            "--help",
            "docker compose",
        ] {
            assert!(version_args(tool).is_err());
        }
    }
}
