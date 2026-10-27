//! D1: selection precedence of the packaged Docker 29.9.2 / Buildx 0.38.1 CLI.
//! This proves selection, not successful builds, credential safety or release acceptance.
//! No daemon socket or operator configuration is ever mounted into the candidate.

use super::*;

const UNTRUSTED: &str = "BUILDX_BUILDER=synthetic-untrusted";
const BUILDKIT: &str = "BUILDKIT_HOST=unix:///synthetic/untrusted-buildkit.sock";
const LOCAL_FAILURE: &str = "ERROR: failed to connect to the docker API at unix:///synthetic/nonexistent.sock; check if the path is correct and if the daemon is running: dial unix /synthetic/nonexistent.sock: connect: no such file or directory";

// Dedicated negative build probe: exact status 1, bounded private Driver captures,
// and unconditional cancellation-ignoring removal before any diagnostic assertions.
fn build_failure(
    driver: &mut Driver,
    image: &str,
    mount: &str,
    poison: &[&str],
    explicit: bool,
) -> Result<String> {
    let identity = driver
        .logs
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid builder probe identity")?;
    let name = format!("devsecops-builder-{identity}-{}", driver.sequence);
    let mut args = vec![
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
        "DOCKER_CONFIG=/tmp/docker",
        "--env",
        "BUILDX_CONFIG=/tmp/buildx",
        "--mount",
        mount,
    ];
    for value in poison {
        args.extend(["--env", value]);
    }
    args.extend([
        image,
        "--host",
        "unix:///synthetic/nonexistent.sock",
        "buildx",
        "build",
    ]);
    if explicit {
        args.extend(["--builder", "default"]);
    }
    args.extend([
        "--load",
        "--progress=plain",
        "--file",
        "/fixture/Dockerfile",
        "/fixture",
    ]);
    let result = driver.docker_exit(&args, 30, false, 1);
    // Also attempted after spawn errors, timeout, output overflow or cancellation.
    let cleanup = driver.docker(&["rm", "--force", &name], 10, true);
    let stdout = container_output(result, cleanup)?;
    let stem = stdout
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix("-stdout.log"))
        .ok_or("invalid builder capture path")?;
    let stderr = stdout.with_file_name(format!("{stem}-stderr.log"));
    // Captures are created mode 0600 and capped per stream by Driver::execute.
    if !fs::read(stdout)
        .map_err(|_| "cannot read builder stdout")?
        .is_empty()
    {
        return Err("unexpected builder stdout; private logs retained");
    }
    fs::read_to_string(stderr).map_err(|_| "cannot read builder stderr")
}

#[test]
#[ignore = "requires authorized native local Docker; builds the pinned packaged CLI"]
fn explicit_default_overrides_synthetic_builder_selection() -> Result<()> {
    let mut driver = Driver::new()?;
    let image = driver.check("docker")?;
    let fixture = driver.logs.join("builder-fixture");
    DirBuilder::new()
        .mode(0o700)
        .create(&fixture)
        .map_err(|_| "cannot create private builder fixture")?;
    let dockerfile = fixture.join("Dockerfile");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(&dockerfile)
        .and_then(|mut file| {
            file.write_all(b"FROM scratch\n")?;
            file.set_permissions(fs::Permissions::from_mode(0o444))
        })
        .map_err(|_| "cannot write synthetic Dockerfile")?;
    // Only the synthetic file is mounted; its containing host dirs stay 0700.
    let mount = format!(
        "type=bind,src={},dst=/fixture/Dockerfile,readonly",
        dockerfile.to_str().ok_or("invalid builder fixture path")?
    );
    // BUILDKIT_HOST alone also hit the local socket in this fixture; it cannot
    // independently demonstrate selection precedence before a daemon connection.
    for poison in [&[UNTRUSTED][..], &[UNTRUSTED, BUILDKIT][..]] {
        let inherited = build_failure(&mut driver, &image, &mount, poison, false)?;
        if inherited.trim() != "ERROR: no builder \"synthetic-untrusted\" found" {
            return Err("implicit build did not fail exclusively on the synthetic builder name");
        }
        let explicit = build_failure(&mut driver, &image, &mount, poison, true)?;
        // Exact diagnostic excludes the untrusted name/host AND arbitrary failures
        // (including permission, config, plugin, context or runtime failures).
        if explicit.trim() != LOCAL_FAILURE {
            return Err("explicit default did not fail exclusively on the synthetic local socket");
        }
    }
    if driver.cancelled.load(Ordering::Relaxed) {
        return Err("builder probe cancelled");
    }
    Ok(())
}
