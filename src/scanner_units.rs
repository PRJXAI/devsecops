#![forbid(unsafe_code)]
//! Internal build-only runner for the two pinned suppliers' official unit scope.
//! Both upstream .make/main.go files exclude **/test/** from units. Privileged
//! integration suites are not silently renamed unit successes; packaged native
//! integration contracts remain independently mandatory in the release driver.
use std::{
    io::Read,
    process::{Command, Stdio},
};

const GO: &str = "/usr/local/go/bin/go";
const TAGS: &str = "-tags=containers_image_openpgp,exclude_graphdriver_btrfs";
const LIMIT: u64 = 8 * 1024 * 1024;

fn prefix(tool: &str) -> Result<&'static str, &'static str> {
    match tool {
        "syft" => Ok("github.com/anchore/syft"),
        "grype" => Ok("github.com/anchore/grype"),
        _ => Err("unsupported fixed scanner unit scope"),
    }
}

fn packages(data: &[u8], tool: &str) -> Result<Vec<String>, &'static str> {
    if data.len() as u64 > LIMIT {
        return Err("package list byte limit");
    }
    let prefix = prefix(tool)?;
    let mut units = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for package in std::str::from_utf8(data)
        .map_err(|_| "invalid package list")?
        .lines()
    {
        if !(package == prefix
            || package
                .strip_prefix(prefix)
                .is_some_and(|p| p.starts_with('/')))
            || !package
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            || package.split('/').any(|p| matches!(p, "" | "." | ".."))
            || !seen.insert(package)
            || seen.len() > 4096
        {
            return Err("foreign, duplicate or excessive package list");
        }
        if !package.split('/').any(|part| part == "test") {
            units.push(package.to_owned());
        }
    }
    if units.is_empty() {
        return Err("missing upstream unit packages");
    }
    Ok(units)
}

fn mode(args: &[String]) -> Result<(&str, bool), &'static str> {
    let (tool, compile) = match args {
        [tool] => (tool.as_str(), false),
        [tool, action] if action == "compile" => (tool.as_str(), true),
        _ => return Err("one fixed scanner identity and optional compile action required"),
    };
    prefix(tool)?;
    Ok((tool, compile))
}

fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (tool, compile) = mode(&args)?;
    if std::env::consts::OS != "linux" {
        return Err("native Linux build-only command");
    }
    let mut child = Command::new(GO)
        .args(["list", TAGS, "./..."])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| "cannot list upstream packages")?;
    let mut data = Vec::new();
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        child.wait().map_err(|_| "package listing cleanup failed")?;
        return Err("missing package stream");
    };
    let read = stdout.take(LIMIT + 1).read_to_end(&mut data);
    if read.is_err() || data.len() as u64 > LIMIT {
        let _ = child.kill();
        child.wait().map_err(|_| "package listing cleanup failed")?;
        return Err("package listing failed or exceeded byte limit");
    }
    if !child
        .wait()
        .map_err(|_| "cannot wait for package listing")?
        .success()
    {
        return Err("upstream package listing failed");
    }
    let units = packages(&data, tool)?;
    if compile {
        println!(
            "Compile-only: {} upstream unit packages; no test execution or acceptance",
            units.len()
        );
        // Unique output per package avoids Go's duplicate test-binary basenames.
        // Keep only compiler cache: no test binary belongs in a supplier layer.
        for (index, package) in units.iter().enumerate() {
            let output = format!("/tmp/scanner-unit-{tool}-{index}.test");
            let status = Command::new(GO)
                .args(["test", "-c", "-race", "-p=1", TAGS, "-o", &output, package])
                .status()
                .map_err(|_| "cannot compile upstream unit package")?;
            match std::fs::remove_file(&output) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (), // no test files
                Err(_) => return Err("unit binary cleanup failed"),
            }
            if !status.success() {
                return Err("upstream unit compilation failed");
            }
        }
        return Ok(());
    }
    println!(
        "Upstream unit scope: {} packages; official **/test/** integration boundary retained",
        units.len()
    );
    if !Command::new(GO)
        .args(["test", "-race", "-count=1", "-p=1", TAGS])
        .args(&units)
        .status()
        .map_err(|_| "cannot execute upstream unit race suite")?
        .success()
    {
        return Err("upstream unit race suite failed");
    }
    Ok(())
}

fn main() {
    if let Err(reason) = run() {
        eprintln!("Scanner unit build gate blocked: {reason}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compilation_is_explicit_and_cannot_select_or_skip_test_packages() {
        assert_eq!(mode(&["syft".into()]).unwrap(), ("syft", false));
        assert_eq!(
            mode(&["grype".into(), "compile".into()]).unwrap(),
            ("grype", true)
        );
        for args in [
            vec![],
            vec!["other"],
            vec!["syft", "-run=x"],
            vec!["syft", "compile", "some/package"],
        ] {
            assert!(mode(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err());
        }
    }
    #[test]
    fn every_unit_package_is_retained_and_only_official_test_directories_are_excluded() {
        let input = b"github.com/anchore/syft\ngithub.com/anchore/syft/cmd/syft\ngithub.com/anchore/syft/internal/test/integration\ngithub.com/anchore/syft/internal/testutils\ngithub.com/anchore/syft/syft/pkg/cataloger\ngithub.com/anchore/syft/test/cli\n";
        assert_eq!(
            packages(input, "syft").unwrap(),
            [
                "github.com/anchore/syft",
                "github.com/anchore/syft/cmd/syft",
                "github.com/anchore/syft/internal/testutils",
                "github.com/anchore/syft/syft/pkg/cataloger",
            ]
        );
        assert_eq!(
            packages(b"github.com/anchore/grype/grype/matcher\n", "grype")
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn unknown_empty_foreign_duplicate_and_argument_injection_never_satisfy_units() {
        for input in [
            b"".as_slice(),
            b"github.com/anchore/syft/test/cli\n",
            b"github.com/anchore/syft-other/x\n",
            b"-run=Selected\n",
            b"github.com/anchore/syft/a b\n",
            b"github.com/anchore/syft/../x\n",
            b"github.com/anchore/syft\ngithub.com/anchore/syft\n",
            b"\xff",
        ] {
            assert!(packages(input, "syft").is_err());
        }
        assert!(packages(b"github.com/anchore/syft\n", "unknown").is_err());
        assert!(packages(&vec![b'x'; LIMIT as usize + 1], "syft").is_err());
    }
}
