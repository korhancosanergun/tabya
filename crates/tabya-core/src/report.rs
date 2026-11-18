//! Report assembly and machine-readable output.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::engine::{Context, Finding, Status};
use crate::model::Severity;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub errors: usize,
    pub not_applicable: usize,
    /// Passed checks as a percentage of checks that produced a verdict.
    pub score_percent: u8,
}

impl Summary {
    pub fn of(findings: &[Finding]) -> Self {
        let count = |status: Status| findings.iter().filter(|f| f.status == status).count();
        let passed = count(Status::Pass);
        let failed = count(Status::Fail);
        let judged = passed + failed;
        Summary {
            total: findings.len(),
            passed,
            failed,
            errors: count(Status::Error),
            not_applicable: count(Status::NotApplicable),
            score_percent: (passed * 100).checked_div(judged).unwrap_or(0) as u8,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub version: &'static str,
    pub platform: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_root: Option<String>,
    pub generated_at_unix: u64,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(ctx: &Context, findings: Vec<Finding>) -> Self {
        Report {
            tool: "tabya",
            version: env!("CARGO_PKG_VERSION"),
            platform: ctx.platform().map_or("unsupported", |p| p.as_str()),
            offline_root: ctx
                .is_offline()
                .then(|| ctx.root().to_string_lossy().into_owned()),
            generated_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            summary: Summary::of(&findings),
            findings,
        }
    }

    /// Highest severity among failed checks.
    pub fn worst_failure(&self) -> Option<Severity> {
        self.findings
            .iter()
            .filter(|f| f.status == Status::Fail)
            .map(|f| f.severity)
            .max()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serializes to JSON")
    }
}
