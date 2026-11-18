use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::model::{Check, Expect, Platform, Rule, Scalar, Severity};
use crate::probe::{self, Observation};

/// Where an audit reads its state from.
#[derive(Debug, Clone)]
pub struct Context {
    root: PathBuf,
    offline: bool,
}

impl Context {
    /// Audit the machine tabya is running on.
    pub fn host() -> Self {
        Context {
            root: PathBuf::from("/"),
            offline: false,
        }
    }

    /// Audit a Linux filesystem tree mounted or unpacked at `root`
    /// (a disk image, a container rootfs, a backup).
    pub fn offline_root(root: impl Into<PathBuf>) -> Self {
        Context {
            root: root.into(),
            offline: true,
        }
    }

    pub fn is_offline(&self) -> bool {
        self.offline
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Platform whose rules apply to this context.
    pub fn platform(&self) -> Option<Platform> {
        if self.offline {
            Some(Platform::Linux)
        } else {
            Platform::current()
        }
    }

    /// Maps an absolute path from a rule onto the audited tree.
    pub(crate) fn resolve(&self, absolute: &str) -> PathBuf {
        if self.offline {
            self.root.join(absolute.trim_start_matches('/'))
        } else {
            PathBuf::from(absolute)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    /// The checked component does not exist on this system.
    NotApplicable,
    /// The state could not be read (typically missing privileges).
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

/// Evaluates every rule that targets the context's platform, in rule order.
pub fn audit(rules: &[Rule], ctx: &Context) -> Vec<Finding> {
    let platform = ctx.platform();
    rules
        .iter()
        .filter(|rule| Some(rule.platform) == platform)
        .map(|rule| evaluate(rule, ctx))
        .collect()
}

fn evaluate(rule: &Rule, ctx: &Context) -> Finding {
    let (observation, expect, default) = match &rule.check {
        Check::Sysctl { key, expect } => (probe::fs::sysctl(ctx, key), Some(expect), None),
        Check::SshdConfig {
            key,
            expect,
            default,
        } => (
            probe::sshd::lookup(ctx, key),
            Some(expect),
            default.as_ref(),
        ),
        Check::FileMode {
            path,
            max_mode,
            owner_uid,
        } => (
            probe::fs::file_mode(ctx, path, max_mode, *owner_uid),
            None,
            None,
        ),
        Check::FileMatch {
            path,
            pattern,
            expect,
            default,
        } => (
            probe::fs::file_match(ctx, path, pattern),
            Some(expect),
            default.as_ref(),
        ),
        Check::Registry {
            hive,
            key,
            value,
            expect,
            default,
        } => (
            probe::registry::read(*hive, key, value),
            Some(expect),
            default.as_ref(),
        ),
    };

    let mut finding = Finding {
        id: rule.id.clone(),
        title: rule.title.clone(),
        severity: rule.severity,
        status: Status::Error,
        expected: expect.map(Expect::describe),
        observed: None,
        detail: None,
        rationale: rule.rationale.clone(),
        remediation: rule.remediation.clone(),
        references: rule.references.clone(),
    };
    judge(&mut finding, observation, expect, default);
    finding
}

fn judge(
    finding: &mut Finding,
    observation: Observation,
    expect: Option<&Expect>,
    default: Option<&Scalar>,
) {
    match observation {
        Observation::Value(value) => {
            finding.status = verdict(expect, &value);
            finding.observed = Some(value);
        }
        Observation::Absent(reason) => match default {
            Some(default) => {
                finding.status = verdict(expect, &default.0);
                finding.observed = Some(default.0.clone());
                finding.detail = Some(format!("{reason}; built-in default assumed"));
            }
            None => {
                finding.status = Status::Fail;
                finding.detail = Some(reason);
            }
        },
        Observation::Verdict {
            pass,
            observed,
            expected,
        } => {
            finding.status = if pass { Status::Pass } else { Status::Fail };
            finding.observed = Some(observed);
            finding.expected = Some(expected);
        }
        Observation::NotApplicable(reason) => {
            finding.status = Status::NotApplicable;
            finding.detail = Some(reason);
        }
        Observation::Error(reason) => {
            finding.status = Status::Error;
            finding.detail = Some(reason);
        }
    }
}

fn verdict(expect: Option<&Expect>, observed: &str) -> Status {
    match expect {
        Some(expect) if expect.matches(observed) => Status::Pass,
        Some(_) => Status::Fail,
        // A value-producing probe without an expectation cannot be judged.
        None => Status::Error,
    }
}
