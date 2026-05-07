// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use clap::{
    Parser, ValueEnum,
    builder::{PossibleValuesParser, TypedValueParser},
};
use regex::Regex;
use semver::{Prerelease, Version};

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "build tasks")]
enum Xtask {
    #[command(about = "bump the global version number and open a pull request")]
    #[command(arg_required_else_help = true)]
    Bump {
        #[clap(long, help = "Allow non-main git branch or dirty tree")]
        dirty: bool,
        #[clap(value_parser = bump_place_parser())]
        place: VersionPlace,
    },
    #[command(about = "tag a release and bump the global version number")]
    #[command(arg_required_else_help = true)]
    Release {
        #[clap(long, help = "Allow non-main git branch or dirty tree")]
        dirty: bool,
        place: VersionPlace,
    },
}

#[derive(Clone, PartialEq, ValueEnum)]
enum VersionPlace {
    Major,
    Minor,
    Patch,
    Pre,
}

fn bump_place_parser() -> impl TypedValueParser<Value = VersionPlace> {
    PossibleValuesParser::new(["major", "minor", "patch"]).map(|place| match place.as_str() {
        "major" => VersionPlace::Major,
        "minor" => VersionPlace::Minor,
        "patch" => VersionPlace::Patch,
        _ => unreachable!("parser only accepts major, minor, or patch"),
    })
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    match Xtask::parse() {
        Xtask::Bump { dirty, place } => bump(&place, dirty),
        Xtask::Release { dirty, place } => release(&place, dirty),
    }
}

fn bump(place: &VersionPlace, dirty: bool) -> Result<(), String> {
    let root_path = workspace_root();
    ensure_release_state(&root_path, dirty)?;

    let old_version = read_workspace_version(&root_path)?;
    let bump_result = bump_on_pr_branch(&root_path, &old_version, place)?;

    let undo_command = [
        format!("git checkout {}", shell_quote(&bump_result.original_branch)),
        format!("git branch -D {}", shell_quote(&bump_result.bump_branch)),
    ]
    .join(" && ");

    println!();
    println!("If you would like to undo:");
    println!("  {undo_command}");
    println!();
    println!("If this looks good, push and publish the PR:");
    println!("  {}", bump_result.publish_command);
    println!();

    Ok(())
}

fn release(place: &VersionPlace, dirty: bool) -> Result<(), String> {
    let root_path = workspace_root();
    ensure_release_state(&root_path, dirty)?;

    let old_version = read_workspace_version(&root_path)?;
    let current_commit = git_output(&root_path, ["rev-parse", "HEAD"])?;
    let current_branch = git_output(&root_path, ["branch", "--show-current"])?;
    let release_tag = match place {
        VersionPlace::Pre => next_alpha_tag(&root_path, &old_version)?,
        _ => format!("v{}", old_version),
    };
    let previous_tag = previous_tag(&root_path, &release_tag)?;
    let repo_url = repo_url(&root_path)?;
    let compare_url = format!("{}/compare/{}...{}", repo_url, previous_tag, current_commit);

    println!(
        "Tagging {current_commit} on {current_branch} as {release_tag}\n - Preview diff: {}",
        compare_url
    );
    git_status(&root_path, ["tag", &release_tag])?;

    if *place == VersionPlace::Pre {
        println!();
        println!("If you would like to undo:");
        println!("  git tag -d {}", shell_quote(&release_tag));
        println!();
        println!("If this looks good, push the tag:");
        println!("  git push origin {}", shell_quote(&release_tag));
        println!();
        return Ok(());
    }

    let bump_result = bump_on_pr_branch(&root_path, &old_version, place)?;

    let undo_command = [
        format!("git tag -d {}", shell_quote(&release_tag)),
        format!("git branch -D {}", shell_quote(&bump_result.bump_branch)),
    ]
    .join(" && ");
    let publish_command = [
        bump_result.publish_command,
        format!("git push -q origin {}", shell_quote(&release_tag)),
    ]
    .join(" && \\\n    ");

    println!();
    println!("If you would like to undo:");
    println!("  {undo_command}");
    println!();
    println!("If this looks good, push and publish the PR:");
    println!("  {publish_command}");
    println!();

    Ok(())
}

struct BumpPrBranch {
    bump_branch: String,
    original_branch: String,
    publish_command: String,
}

fn bump_on_pr_branch(
    root_path: &Path,
    old_version: &Version,
    place: &VersionPlace,
) -> Result<BumpPrBranch, String> {
    let original_branch = git_output(root_path, ["branch", "--show-current"])?;
    let new_version = old_version.clone().up(place);
    let bump_branch = format!("bump_v{}", new_version);
    git_status(root_path, ["checkout", "-b", &bump_branch])?;

    println!("Bumping version number from {old_version} to {new_version}");
    bump_package_versions(root_path, &new_version)?;

    let commit_message = format!("Bump to v{}", new_version);
    git_status(root_path, ["add", "Cargo.toml", "Cargo.lock"])?;
    git_status(root_path, ["commit", "-m", commit_message.as_str()])?;
    git_status(root_path, ["checkout", &original_branch])?;

    let quoted_bump_branch = shell_quote(&bump_branch);
    let quoted_commit_message = shell_quote(&commit_message);
    let push_command = format!("git push -q -u origin {quoted_bump_branch}");
    let pr_command = [
        "gh pr create --web --base main".to_string(),
        format!("--head {quoted_bump_branch}"),
        format!("--title {quoted_commit_message}"),
    ]
    .join(" ");
    let publish_command = [push_command, pr_command].join(" && \\\n    ");

    Ok(BumpPrBranch {
        bump_branch,
        original_branch,
        publish_command,
    })
}

fn bump_package_versions(root_path: &Path, version: &Version) -> Result<(), String> {
    update_workspace_version(root_path, version)?;

    println!("Running cargo check to update Cargo.lock...");
    let status = Command::new("cargo")
        .arg("check")
        .arg("-q")
        .current_dir(root_path)
        .status()
        .map_err(|e| format!("failed to run cargo check: {}", e))?;
    if !status.success() {
        return Err("cargo check failed".to_string());
    }

    Ok(())
}

fn ensure_release_state(root_path: &Path, dirty: bool) -> Result<(), String> {
    let branch = git_output(root_path, ["branch", "--show-current"])?;
    if branch != "main" && !dirty {
        return Err(format!(
            "task must be run from main, currently on {}",
            branch
        ));
    }

    let status = git_output(root_path, ["status", "--porcelain", "--untracked-files=no"])?;
    if !status.is_empty() && !dirty {
        return Err("task requires no modified tracked files".to_string());
    }

    git_status(
        root_path,
        ["fetch", "origin", "main:refs/remotes/origin/main", "--tags"],
    )?;

    let local_main = git_output(root_path, ["rev-parse", "main"])?;
    let origin_main = git_output(root_path, ["rev-parse", "origin/main"])?;
    if local_main != origin_main {
        return Err([
            "Your local main does not match origin/main.".to_string(),
            format!("main:        {local_main:.7}"),
            format!("origin/main: {origin_main:.7}"),
            "Probably need to `git pull`".to_string(),
        ]
        .join("\n"));
    }

    Ok(())
}

fn read_workspace_version(root_path: &Path) -> Result<Version, String> {
    let cargo_toml = root_path.join("Cargo.toml");
    let contents = fs::read_to_string(cargo_toml).map_err(|e| e.to_string())?;
    let version_pattern = Regex::new(r#"(?m)^version = "(.*)"$"#).unwrap();
    let version_line = version_pattern
        .captures(&contents)
        .ok_or("could not find workspace package version")?;
    version_line
        .get(1)
        .unwrap()
        .as_str()
        .parse()
        .map_err(|e| format!("failed to parse workspace version: {}", e))
}

fn update_workspace_version(root_path: &Path, version: &Version) -> Result<(), String> {
    let cargo_toml = root_path.join("Cargo.toml");
    let contents = fs::read_to_string(&cargo_toml).map_err(|e| e.to_string())?;
    let version_pattern = Regex::new(r#"(?m)^version = "(.*)"$"#).unwrap();
    let version_line = version_pattern
        .captures(&contents)
        .ok_or("could not find workspace package version")?;
    let old_version_line = version_line.get(0).unwrap().as_str();
    let new_version_line = format!(r#"version = "{}""#, version);
    let new_contents = contents.replace(old_version_line, &new_version_line);
    fs::write(cargo_toml, new_contents).map_err(|e| e.to_string())?;
    println!("Updated workspace to {}", version);
    Ok(())
}

fn next_alpha_tag(root_path: &Path, version: &Version) -> Result<String, String> {
    let base = format!("v{}-alpha", version);
    let tags = git_output(root_path, ["tag", "--list", &format!("{}*", base)])?;
    let next = tags
        .lines()
        .filter_map(|tag| tag.strip_prefix(&base))
        .filter_map(|suffix| suffix.strip_prefix('.'))
        .filter_map(|number| number.parse::<u64>().ok())
        .max()
        .map(|number| number + 1)
        .unwrap_or(1);
    Ok(format!("{}.{}", base, next))
}

fn previous_tag(root_path: &Path, release_tag: &str) -> Result<String, String> {
    let tags = git_output(root_path, ["tag", "--sort=-version:refname"])?;
    tags.lines()
        .find(|tag| *tag != release_tag)
        .map(ToString::to_string)
        .ok_or("could not find previous release tag".to_string())
}

fn repo_url(root_path: &Path) -> Result<String, String> {
    let url = git_output(root_path, ["remote", "get-url", "origin"])?;
    if let Some(path) = url.strip_prefix("git@github.com:") {
        return Ok(format!(
            "https://github.com/{}",
            path.strip_suffix(".git").unwrap_or(path)
        ));
    }
    Ok(url.strip_suffix(".git").unwrap_or(&url).to_string())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'\''"#))
}

fn git_output<const N: usize>(root_path: &Path, args: [&str; N]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root_path)
        .output()
        .map_err(|e| format!("failed to run git: {}", e))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_status<const N: usize>(root_path: &Path, args: [&str; N]) -> Result<(), String> {
    let status = Command::new("git")
        .args(args)
        .current_dir(root_path)
        .status()
        .map_err(|e| format!("failed to run git: {}", e))?;
    if !status.success() {
        return Err(format!("git {} failed", args.join(" ")));
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    let xtask_path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    xtask_path.parent().unwrap().to_path_buf()
}

trait Bump {
    fn up(self, place: &VersionPlace) -> Self;
}

impl Bump for Version {
    fn up(mut self, place: &VersionPlace) -> Self {
        match place {
            VersionPlace::Major => {
                if self.pre == Prerelease::EMPTY {
                    self.major += 1;
                    self.minor = 0;
                    self.patch = 0;
                }
                self.pre = Prerelease::EMPTY;
            }
            VersionPlace::Minor => {
                if self.pre == Prerelease::EMPTY {
                    self.minor += 1;
                    self.patch = 0;
                }
                self.pre = Prerelease::EMPTY;
            }
            VersionPlace::Patch => {
                if self.pre == Prerelease::EMPTY {
                    self.patch += 1;
                }
                self.pre = Prerelease::EMPTY;
            }
            VersionPlace::Pre => match self.pre.as_str().split_once('.') {
                Some((label, number)) => {
                    let num = number.parse::<u64>().unwrap();
                    self.pre = Prerelease::new(&format!("{}.{}", label, num + 1)).unwrap();
                }
                None if self.pre == Prerelease::EMPTY => {
                    self.patch += 1;
                    self.pre = Prerelease::new("alpha.1").unwrap();
                }
                None => panic!("Found unexpected prerelease format: {}", self.pre),
            },
        }

        self
    }
}
