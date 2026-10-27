#![forbid(unsafe_code)]

mod audit;
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

fn reap_until(child: &mut Child, limit: Duration) -> Result<()> {
    // A kill request is not a reap. Give the final kill its own bounded wait too.
    for force in [false, true] {
        if force {
            let _ = child.kill();
        }
        let start = Instant::now();
        loop {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return Ok(());
            }
            // Monitoring errors must not bypass the final kill/reap attempt.
            if start.elapsed() >= limit {
                break;
            }
            thread::sleep(POLL);
        }
    }
    Err("command reaping was not confirmed")
}

fn terminate(child: &mut Child) -> Result<()> {
    // Current rustix features have no process API. Invoke kill directly, never a shell.
    let group = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{}", child.id())])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| "cannot start process-group cleanup")
        .and_then(|mut killer| reap_until(&mut killer, Duration::from_secs(2)));
    // A nonzero kill status can mean the group already exited. Always reap the
    // direct child, even if launching/reaping the external group killer failed.
    let _ = child.kill();
    let reaped = reap_until(child, Duration::from_secs(2));
    group.and(reaped)
}

fn container_output(result: Result<PathBuf>, cleanup: Result<PathBuf>) -> Result<PathBuf> {
    match (result, cleanup) {
        (Err(_), Err(_)) => Err("check failed and container cleanup was not confirmed"),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(_)) => Err("container cleanup failed; private logs retained"),
        (Ok(path), Ok(_)) => Ok(path),
    }
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
        self.docker_exit(args, seconds, cleanup, 0)
    }

    fn docker_exit(
        &mut self,
        args: &[&str],
        seconds: u64,
        cleanup: bool,
        expected_exit: i32,
    ) -> Result<PathBuf> {
        let mut command = Command::new("docker");
        command.args(args).current_dir(&self.root);
        self.execute(command, seconds, cleanup, expected_exit)
    }

    // Reserved for bounded host Cargo/Git fixtures, not arbitrary host programs.
    #[allow(dead_code)]
    fn host(&mut self, program: &str, args: &[&str], seconds: u64) -> Result<PathBuf> {
        if !matches!(program, "cargo" | "git") {
            return Err("unsupported host command");
        }
        let mut command = Command::new(program);
        command.args(args).current_dir(&self.root);
        self.execute(command, seconds, false, 0)
    }

    fn execute(
        &mut self,
        mut command: Command,
        seconds: u64,
        cleanup: bool,
        expected_exit: i32,
    ) -> Result<PathBuf> {
        if !(0..=255).contains(&expected_exit) {
            return Err("invalid expected exit code");
        }
        if !cleanup && self.cancelled.load(Ordering::Relaxed) {
            return Err("check cancelled");
        }
        self.sequence += 1;
        let stdout_path = self.logs.join(format!("{}-stdout.log", self.sequence));
        let (mut stdout, out) = Log::new(&stdout_path)?;
        let (mut stderr, err) = Log::new(&self.logs.join(format!("{}-stderr.log", self.sequence)))?;
        let mut child = command
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .process_group(0)
            .spawn()
            .map_err(|_| "cannot start command; private logs retained")?;
        // Command retains its configured writer descriptors across spawn.
        drop(command);
        let start = Instant::now();
        let result = (|| {
            let mut status = None;
            loop {
                if !cleanup && self.cancelled.load(Ordering::Relaxed) {
                    return Err("check cancelled");
                }
                if start.elapsed() >= Duration::from_secs(seconds) {
                    return Err("command timed out");
                }
                stdout.drain()?;
                stderr.drain()?;
                if status.is_none() {
                    status = child.try_wait().map_err(|_| "cannot monitor command")?;
                }
                if let Some(status) = status.filter(|_| stdout.eof && stderr.eof) {
                    return if status.code() == Some(expected_exit) {
                        Ok(())
                    } else {
                        Err("unexpected command exit; private logs retained")
                    };
                }
                thread::sleep(POLL);
            }
        })();
        if result.is_err() && terminate(&mut child).is_err() {
            return Err("command failed and process cleanup was not confirmed");
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
        let output = container_output(result, cleanup)?;
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
    if args.as_slice() == ["audit-dependencies"] {
        if let Err(error) = Driver::new().and_then(|mut driver| audit::gate(&mut driver)) {
            eprintln!("dependency audit failed: {error}");
            std::process::exit(1);
        }
        return;
    }
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
            eprintln!(
                "usage: devsecops check TOOL | check-all | audit-dependencies | prepare-release | publish-all"
            );
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
    use super::*;

    // The test executable is the only fixture executable. Each invocation runs
    // exactly this ignored test in a fresh process; no shell or Docker is used.
    fn fixture(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "tests::process_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("DEVSECOPS_FIXTURE", mode);
        command
    }

    fn marker(command: &mut Command, path: &Path) {
        command.env("DEVSECOPS_FIXTURE_MARKER", path);
    }

    fn mark() {
        if let Some(path) = std::env::var_os("DEVSECOPS_FIXTURE_MARKER") {
            fs::write(path, std::process::id().to_string()).unwrap();
        }
    }

    fn kill_command(pid: &str, signal: &str) -> Child {
        Command::new("/bin/kill")
            .args([signal, "--", pid])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap()
    }

    fn assert_stopped(pid: &str) {
        let start = Instant::now();
        loop {
            // An orphan can briefly remain an init-owned zombie on Linux. It
            // cannot run/hold streams; only its adopting parent can reap it.
            #[cfg(target_os = "linux")]
            match fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                Ok(stat) if stat.rsplit_once(") ").unwrap().1.starts_with('Z') => return,
                _ => (),
            }
            let mut probe = kill_command(pid, "-0");
            reap_until(&mut probe, Duration::from_secs(1)).unwrap();
            if !probe.try_wait().unwrap().unwrap().success() {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "fixture still running"
            );
            thread::sleep(POLL);
        }
    }

    fn assert_private_logs(driver: &Driver) {
        assert_eq!(
            fs::metadata(&driver.logs).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for entry in fs::read_dir(&driver.logs).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().is_some_and(|ext| ext == "log") {
                let metadata = entry.metadata().unwrap();
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
                assert!(metadata.len() <= LOG_LIMIT as u64);
            }
        }
    }

    #[test]
    #[ignore = "Rust subprocess fixture, invoked only by lifecycle tests"]
    fn process_fixture() {
        let mode = std::env::var("DEVSECOPS_FIXTURE").unwrap();
        match mode.as_str() {
            "exit" => {
                mark();
                println!("synthetic-private-stdout");
                eprintln!("synthetic-private-stderr");
                let code = std::env::var("DEVSECOPS_FIXTURE_EXIT")
                    .unwrap_or_else(|_| "0".into())
                    .parse()
                    .unwrap();
                std::process::exit(code);
            }
            "stdout-overflow" | "stderr-overflow" => {
                let mut stream: Box<dyn Write> = if mode == "stdout-overflow" {
                    Box::new(std::io::stdout())
                } else {
                    Box::new(std::io::stderr())
                };
                for _ in 0..=(LOG_LIMIT / 8192) {
                    if stream.write_all(&[b'x'; 8192]).is_err() {
                        break;
                    }
                }
            }
            "hang" => {
                mark();
                thread::sleep(Duration::from_secs(30));
            }
            "descendant" => {
                // Deliberately exit before an inherited stdout/stderr writer.
                // The descendant remains in execute's process group.
                // This fixture intentionally exits without waiting, modelling
                // an orphaned stream-holding descendant (bounded to 30 seconds).
                #[allow(clippy::zombie_processes)]
                let _child = fixture("hang").spawn().unwrap();
                std::process::exit(0);
            }
            "signal-driver" => {
                let mut driver = Driver::new().unwrap();
                let result = driver.execute(fixture("hang"), 15, false, 0);
                assert_eq!(result, Err("check cancelled"));
                assert_eq!(
                    driver.execute(fixture("exit"), 2, false, 0),
                    Err("check cancelled")
                );
                let mut cleanup = fixture("exit");
                marker(
                    &mut cleanup,
                    &PathBuf::from(std::env::var_os("DEVSECOPS_FIXTURE_CLEANUP").unwrap()),
                );
                assert!(driver.execute(cleanup, 2, true, 0).is_ok());
                assert_private_logs(&driver);
            }
            "signal-exit" => {
                let mut killer = kill_command(&std::process::id().to_string(), "-TERM");
                reap_until(&mut killer, Duration::from_secs(1)).unwrap();
                panic!("signal did not terminate fixture");
            }
            _ => panic!("unknown Rust fixture"),
        }
    }

    #[test]
    fn exact_exit_codes_and_private_capture() {
        let mut driver = Driver::new().unwrap();
        let mut command = fixture("exit");
        command.env("DEVSECOPS_FIXTURE_EXIT", "7");
        let output = driver.execute(command, 5, false, 7).unwrap();
        assert!(
            fs::read_to_string(output)
                .unwrap()
                .contains("synthetic-private-stdout")
        );
        assert!(
            fs::read_to_string(driver.logs.join("1-stderr.log"))
                .unwrap()
                .contains("synthetic-private-stderr")
        );
        let mut command = fixture("exit");
        command.env("DEVSECOPS_FIXTURE_EXIT", "7");
        assert_eq!(
            driver.execute(command, 5, false, 0),
            Err("unexpected command exit; private logs retained")
        );
        assert_eq!(
            driver.execute(fixture("exit"), 5, false, 7),
            Err("unexpected command exit; private logs retained")
        );
        assert_eq!(
            driver.execute(fixture("signal-exit"), 5, false, 143),
            Err("unexpected command exit; private logs retained")
        );
        assert_eq!(
            driver.execute(fixture("exit"), 5, false, -1),
            Err("invalid expected exit code")
        );
        assert_eq!(
            driver.execute(fixture("exit"), 5, false, 256),
            Err("invalid expected exit code")
        );
        assert_private_logs(&driver);
    }

    #[test]
    fn stdout_and_stderr_overflow_fail_with_private_capped_logs() {
        for (mode, stream) in [("stdout-overflow", "stdout"), ("stderr-overflow", "stderr")] {
            let mut driver = Driver::new().unwrap();
            let start = Instant::now();
            assert_eq!(
                driver.execute(fixture(mode), 30, false, 0),
                Err("command output limit exceeded")
            );
            // Small Unix socket buffers can require many bounded polls to
            // transfer 8 MiB. Use the existing smoke deadline, not larger caps.
            assert!(start.elapsed() < Duration::from_secs(35));
            assert_eq!(
                fs::metadata(driver.logs.join(format!("1-{stream}.log")))
                    .unwrap()
                    .len(),
                LOG_LIMIT as u64
            );
            assert_private_logs(&driver);
        }
    }

    #[test]
    fn silent_hang_and_exited_parent_with_open_descendant_streams_are_bounded() {
        for mode in ["hang", "descendant"] {
            let mut driver = Driver::new().unwrap();
            let pidfile = driver.logs.join("fixture.pid");
            let mut command = fixture(mode);
            marker(&mut command, &pidfile);
            let start = Instant::now();
            assert_eq!(
                driver.execute(command, 1, false, 0),
                Err("command timed out")
            );
            assert!(start.elapsed() < Duration::from_secs(10));
            assert_stopped(fs::read_to_string(pidfile).unwrap().trim());
            assert_private_logs(&driver);
        }
    }

    #[test]
    fn final_kill_is_followed_by_a_bounded_reap() {
        let mut command = fixture("hang");
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id().to_string();
        let start = Instant::now();
        reap_until(&mut child, Duration::from_millis(100)).unwrap();
        let status = child.try_wait().unwrap().unwrap();
        assert!(!status.success());
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_stopped(&pid);
    }

    #[test]
    fn spawn_failure_is_sanitized_and_cleanup_still_runs_after_cancellation() {
        let mut driver = Driver::new().unwrap();
        let result = driver.execute(
            Command::new(driver.logs.join("missing-executable")),
            1,
            false,
            0,
        );
        assert_eq!(result, Err("cannot start command; private logs retained"));
        driver.cancelled.store(true, Ordering::Relaxed);
        let done = driver.logs.join("removed");
        let mut cleanup = fixture("exit");
        marker(&mut cleanup, &done);
        let cleanup = driver.execute(cleanup, 2, true, 0);
        assert_eq!(
            container_output(result, cleanup),
            Err("cannot start command; private logs retained")
        );
        assert!(done.is_file());
        assert_eq!(
            driver.execute(fixture("exit"), 1, false, 0),
            Err("check cancelled")
        );
        assert_private_logs(&driver);
    }

    #[test]
    fn rust_removal_fixtures_preserve_primary_and_cleanup_failures() {
        for primary_exit in [0, 7] {
            for removal in ["exit", "hang", "spawn-failure"] {
                let mut driver = Driver::new().unwrap();
                let mut run = fixture("exit");
                run.env("DEVSECOPS_FIXTURE_EXIT", primary_exit.to_string());
                let result = driver.execute(run, 2, false, 0);
                driver.cancelled.store(true, Ordering::Relaxed);
                let mut rm = if removal == "spawn-failure" {
                    Command::new(driver.logs.join("missing-removal"))
                } else {
                    fixture(removal)
                };
                rm.env("DEVSECOPS_FIXTURE_EXIT", "9");
                let start = Instant::now();
                let cleanup = driver.execute(rm, 1, true, 0);
                assert!(cleanup.is_err());
                assert!(start.elapsed() < Duration::from_secs(10));
                assert_eq!(
                    container_output(result, cleanup),
                    Err(if primary_exit == 0 {
                        "container cleanup failed; private logs retained"
                    } else {
                        "check failed and container cleanup was not confirmed"
                    })
                );
                assert_private_logs(&driver);
            }
        }
    }

    #[test]
    fn sigint_and_sigterm_cancel_the_driver_but_not_cleanup() {
        for signal in ["-INT", "-TERM"] {
            let driver = Driver::new().unwrap();
            let ready = driver.logs.join("ready.pid");
            let cleanup = driver.logs.join("cleanup.pid");
            let mut command = fixture("signal-driver");
            marker(&mut command, &ready);
            command.env("DEVSECOPS_FIXTURE_CLEANUP", &cleanup);
            let mut child = command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .unwrap();
            let start = Instant::now();
            while !ready.is_file() && start.elapsed() < Duration::from_secs(5) {
                thread::sleep(POLL);
            }
            if !ready.is_file() {
                terminate(&mut child).unwrap();
                panic!("signal fixture did not become ready");
            }
            let mut killer = kill_command(&child.id().to_string(), signal);
            reap_until(&mut killer, Duration::from_secs(1)).unwrap();
            assert!(killer.try_wait().unwrap().unwrap().success());
            reap_until(&mut child, Duration::from_secs(5)).unwrap();
            assert!(
                child.try_wait().unwrap().unwrap().success(),
                "signal fixture failed"
            );
            assert!(cleanup.is_file());
            assert_stopped(fs::read_to_string(ready).unwrap().trim());
            assert!(start.elapsed() < Duration::from_secs(10));
        }
    }

    #[test]
    fn host_commands_are_narrow_and_honor_cancellation() {
        let mut driver = Driver::new().unwrap();
        for program in ["sh", "/usr/bin/git", "node", "python", ""] {
            assert_eq!(
                driver.host(program, &[], 1),
                Err("unsupported host command")
            );
        }
        driver.cancelled.store(true, Ordering::Relaxed);
        for program in ["git", "cargo"] {
            assert_eq!(
                driver.host(program, &["--version"], 1),
                Err("check cancelled")
            );
        }
        assert_eq!(driver.sequence, 0);
    }

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
