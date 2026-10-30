//! Two fixed dependency targets discovered by the paired compiler scan.
use super::*;

fn versions(text: &str) -> BTreeMap<&str, &str> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let version = fields.next()?;
            (name.contains('/') && version.starts_with('v')).then_some((name, version))
        })
        .collect()
}
fn change(before: &str, after: &str) -> Result<()> {
    let before = versions(before);
    let after = versions(after);
    if before.len() != after.len() || before.keys().ne(after.keys()) {
        return Err("Syft dependency graph membership changed");
    }
    for (name, old) in before {
        let expected = match name {
            "github.com/go-jose/go-jose/v4" => "v4.1.6",
            "golang.org/x/net" => "v0.62.0",
            _ => old,
        };
        if after.get(name) != Some(&expected) {
            return Err("unreviewed Syft dependency change");
        }
    }
    if after.get("github.com/go-jose/go-jose/v4") != Some(&"v4.1.6")
        || after.get("golang.org/x/net") != Some(&"v0.62.0")
    {
        return Err("missing fixed Syft dependency targets");
    }
    Ok(())
}
/// Discovery only: exact source/compiler/versions and authenticated module retrieval.
/// Result is not a build, test result, locked production recipe or publication input.
pub(super) fn resolve_dependencies(
    driver: &mut Driver,
    name: &str,
    context: &Path,
) -> Result<PathBuf> {
    let before = context.join("before");
    let after = context.join("after");
    mkdir(&before, false)?;
    mkdir(&after, false)?;
    for file in ["go.mod", "go.sum"] {
        let output = driver.docker(&["exec", "--workdir=/src", name, "cat", file], 30, false)?;
        write_new(&before.join(file), &bytes(&output, 1024 * 1024)?, 0o600)?;
    }
    let output = driver.docker(
        &[
            "exec",
            "--workdir=/src",
            "--env=GOFLAGS=",
            name,
            "go",
            "get",
            "github.com/go-jose/go-jose/v4@v4.1.6",
            "golang.org/x/net@v0.62.0",
        ],
        600,
        false,
    )?;
    for file in ["go.mod", "go.sum"] {
        let output = driver.docker(&["exec", "--workdir=/src", name, "cat", file], 30, false)?;
        write_new(&after.join(file), &bytes(&output, 1024 * 1024)?, 0o600)?;
    }
    let old = String::from_utf8(bytes(&before.join("go.mod"), 1024 * 1024)?)
        .map_err(|_| "invalid original module text")?;
    let new = String::from_utf8(bytes(&after.join("go.mod"), 1024 * 1024)?)
        .map_err(|_| "invalid resolved module text")?;
    change(&old, &new)?;
    for prefix in ["go ", "toolchain ", "replace ", "exclude "] {
        if old
            .lines()
            .filter(|line| line.starts_with(prefix))
            .collect::<Vec<_>>()
            != new
                .lines()
                .filter(|line| line.starts_with(prefix))
                .collect::<Vec<_>>()
        {
            return Err("Syft module policy changed");
        }
    }
    let mut patch = Vec::new();
    for file in ["go.mod", "go.sum"] {
        let mut command = Command::new("diff");
        command
            .args(["-u", "-L", &format!("a/{file}"), "-L", &format!("b/{file}")])
            .arg(before.join(file))
            .arg(after.join(file));
        let diff = driver.execute(command, 30, false, 1)?;
        patch.extend_from_slice(&bytes(&diff, 1024 * 1024)?);
    }
    write_new(&context.join("dependencies.patch"), &patch, 0o600)?;
    write_json(
        &context.join("dependency-resolution.json"),
        &json!({"scope":"fixed-version resolution only, not build or adoption","source_archive_sha256":SOURCE_HASH,"compiler":COMPILER,"go_mod_sha256":hash(&after.join("go.mod"),1024 * 1024)?,"go_sum_sha256":hash(&after.join("go.sum"),1024 * 1024)?,"patch_sha256":hash(&context.join("dependencies.patch"),1024 * 1024)?,"release_accepted":false}),
    )?;
    Ok(output)
}
#[test]
fn syft_dependency_resolution_allows_only_two_reviewed_version_changes() {
    let before = "go 1.26.8\nrequire (\n github.com/go-jose/go-jose/v4 v4.1.5\n golang.org/x/net v0.61.0\n golang.org/x/crypto v0.58.0\n)\n";
    let after = before
        .replace("v4.1.5", "v4.1.6")
        .replace("v0.61.0", "v0.62.0");
    change(before, &after).unwrap();
    assert!(change(before, &after.replace("v0.58.0", "v0.59.0")).is_err());
    assert!(change(before, &after.replace(" golang.org/x/crypto v0.58.0\n", "")).is_err());
    assert!(change(before, &after.replace("v0.62.0", "v0.63.0")).is_err());
    assert!(change(before, before).is_err());
}
#[test]
#[ignore = "resolves two exact public Syft dependency targets only; no build or adoption"]
fn resolve_fixed_syft_dependencies() -> Result<()> {
    let mut driver = Driver::new()?;
    driver.native()?;
    let context = driver.logs.join("syft-resolution");
    mkdir(&context, false)?;
    compile(
        &mut driver,
        &context,
        &mut "startup",
        Work::ResolveDependencies,
    )?;
    Ok(())
}
