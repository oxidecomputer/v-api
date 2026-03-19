// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::{Parser, ValueEnum};
use regex::Regex;
use semver::{Prerelease, Version};
use std::fs;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "build tasks")]
enum Xtask {
    #[command(about = "bump the global version number")]
    Bump {
        #[clap(long)]
        place: VersionPlace,
    },
}

#[derive(Clone, ValueEnum)]
enum VersionPlace {
    Minor,
    Major,
    Patch,
    Pre,
}

fn main() -> Result<(), String> {
    let xtask = Xtask::parse();

    match xtask {
        Xtask::Bump { place } => bump_package_versions(&place),
    }
}

fn bump_package_versions(place: &VersionPlace) -> Result<(), String> {
    let packages = vec![
        "v-api",
        "v-api-installer",
        "v-api-param",
        "v-api-permission-derive",
        "v-model",
    ];

    let crate_version_pattern = Regex::new(r#"(?m)^version = "(.*)"$"#).unwrap();

    for package in packages {
        let path = format!("{}/Cargo.toml", package);
        let contents = fs::read_to_string(&path).unwrap();
        let version_line = crate_version_pattern.captures(&contents).unwrap();
        let mut version: Version = version_line.get(1).unwrap().as_str().parse().unwrap();
        version = version.up(place);

        let old_version_line = version_line.get(0).unwrap().as_str();
        let new_version_line = format!(r#"version = "{}""#, version);
        let new_contents = contents.replace(old_version_line, &new_version_line);

        fs::write(path, new_contents).unwrap();

        println!("Updated {} to {}", package, version);
    }

    Ok(())
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
                None => panic!("Found unexpected prelease format: {}", self.pre),
            },
        }

        self
    }
}
