//! Opt-in diagnostic, never a publication prerequisite or timeout retry.
use super::{Driver, Result, container_output};
use serde_json::json;
use std::{fs, os::unix::fs::OpenOptionsExt, process::Command, time::Instant};

fn docker(
    driver: &mut Driver,
    endpoint: &str,
    args: &[&str],
    seconds: u64,
    cleanup: bool,
) -> Result<std::path::PathBuf> {
    let mut command = Command::new("docker");
    command
        .env_remove("DOCKER_CONTEXT")
        .args(["--host", endpoint])
        .args(args);
    driver.execute(command, seconds, cleanup, 0)
}

#[test]
#[ignore = "authorized serial local arm64 exit diagnostic; no mounts/retries/host changes or release approval"]
fn native_loader_and_gitleaks_exit_diagnostic() {
    diagnostic(false, 600);
}

#[test]
#[ignore = "authorized loader-only intermittent exit investigation; stop at first failure, no Gitleaks/Git execution"]
fn native_loader_only_exit_diagnostic() {
    diagnostic(true, 6000);
}

fn diagnostic(loader_only: bool, count: usize) {
    assert!(count <= 6000);
    let mut driver = Driver::new().unwrap();
    let (arch, endpoint) = driver.native().unwrap();
    assert_eq!(arch, "arm64", "the captured input is native arm64 only");
    let image = "sha256:c7b85a850c361ccacdef3f8e237704262a50c4427f0a8b8f5e25a4f315596c9b";
    let inspected = docker(
        &mut driver,
        &endpoint,
        &[
            "image",
            "inspect",
            "--format",
            "{{.Id}} {{.Architecture}}",
            image,
        ],
        15,
        false,
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(inspected).unwrap().trim(),
        format!("{image} arm64")
    );
    docker(
        &mut driver,
        &endpoint,
        &["version", "--format", "{{json .}}"],
        15,
        false,
    )
    .unwrap();
    let identity = driver
        .logs
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let mut observations = vec![];
    let batch_start = Instant::now();
    for index in 0..count {
        assert!(
            batch_start.elapsed().as_secs() < 1800,
            "diagnostic batch budget exhausted"
        );
        let loader = loader_only || index % 2 == 0;
        let name = format!("exit-probe-{identity}-{index}");
        let since = chrono::Utc::now().to_rfc3339();
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
            "--memory=3g",
            "--memory-swap=3g",
            "--cpus=2",
            "--pids-limit=128",
            "--ulimit=nofile=256:256",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777",
            "--workdir=/tmp",
            "--env=HOME=/tmp",
        ];
        if loader {
            args.extend([
                "--entrypoint",
                "/usr/lib/ld-linux-aarch64.so.1",
                image,
                "--version",
            ]);
        } else {
            args.extend([image, "version"]);
        }
        let start = Instant::now();
        let result = docker(&mut driver, &endpoint, &args, 120, false);
        let failed = result.is_err();
        let primary = result.as_ref().err().copied();
        let mut probes = vec![];
        if failed && !driver.cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            for (label, args) in [
                (
                    "state",
                    vec!["inspect", "--format", "{{json .State}}", &name],
                ),
                ("top", vec!["top", &name, "-eo", "pid,ppid,stat,wchan,args"]),
            ] {
                let probe = docker(&mut driver, &endpoint, &args, 15, true);
                probes.push(json!({"kind":label,"captured":probe.is_ok(),"file":probe.ok().and_then(|p|p.file_name().map(|v|v.to_string_lossy().into_owned()))}));
            }
            let until = chrono::Utc::now().to_rfc3339();
            let filter = format!("container={name}");
            let probe = docker(
                &mut driver,
                &endpoint,
                &[
                    "events",
                    "--since",
                    &since,
                    "--until",
                    &until,
                    "--filter",
                    &filter,
                    "--format",
                    "{{json .}}",
                ],
                15,
                true,
            );
            probes.push(json!({"kind":"events","captured":probe.is_ok(),"file":probe.ok().and_then(|p|p.file_name().map(|v|v.to_string_lossy().into_owned()))}));
        }
        let cleanup = docker(&mut driver, &endpoint, &["rm", "--force", &name], 15, true);
        let cleanup_ok = cleanup.is_ok();
        let complete = container_output(result, cleanup);
        observations.push(json!({"case":if loader {"glibc-loader-version"} else {"gitleaks-version"},"completed":complete.is_ok(),"primary_error":primary,"cleanup_confirmed":cleanup_ok,"probes":probes,"elapsed_ms":start.elapsed().as_millis()}));
        if complete.is_err() || index + 1 == count {
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(driver.logs.join("exit-diagnostic.json"))
                .unwrap();
            serde_json::to_writer_pretty(&file,&json!({"image":image,"arch":arch,"observations":observations,"scope":"diagnostic-only; first failure stops; not runtime or release acceptance"})).unwrap();
            file.sync_all().unwrap();
            assert!(
                complete.is_ok(),
                "native exit diagnostic failed; private owned-container evidence retained"
            );
        }
    }
}
