use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use anstyle::{AnsiColor, Style};
use clap::{Parser, Subcommand, ValueEnum};
use tabya_core::report::Report;
use tabya_core::{audit, builtin_rules, parse_rules, Context, Finding, Rule, Severity, Status};

/// Read-only host hardening auditor for Ubuntu and Windows 11.
#[derive(Parser)]
#[command(name = "tabya", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check this host (or an offline Linux root) against the rules
    Audit(AuditArgs),
    /// List the rules that would be evaluated
    List(RuleArgs),
}

#[derive(clap::Args)]
struct RuleArgs {
    /// Additional YAML rule file (repeatable)
    #[arg(short, long, value_name = "FILE")]
    rules: Vec<PathBuf>,

    /// Use only the files given with --rules
    #[arg(long, requires = "rules")]
    no_builtin: bool,
}

#[derive(clap::Args)]
struct AuditArgs {
    #[command(flatten)]
    rules: RuleArgs,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Write the report to a file instead of stdout
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Skip rules below this severity
    #[arg(long, value_name = "SEVERITY", default_value = "info")]
    min_severity: Severity,

    /// Exit with status 1 when a check at or above this severity fails
    /// (info, low, medium, high, critical or never)
    #[arg(long, value_name = "SEVERITY", default_value = "low")]
    fail_on: FailOn,

    /// Audit a Linux filesystem tree at DIR instead of the running host
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,

    /// Show only failed checks and checks that could not be read
    #[arg(long)]
    only_failed: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Clone, Copy)]
enum FailOn {
    Never,
    Severity(Severity),
}

impl FromStr for FailOn {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("never") {
            Ok(FailOn::Never)
        } else {
            Severity::from_str(s).map(FailOn::Severity)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Audit(args) => run_audit(args),
        Command::List(args) => run_list(args),
    };
    match result {
        Ok(code) => code,
        Err(message) => {
            anstream::eprintln!("tabya: {message}");
            ExitCode::from(2)
        }
    }
}

fn load_rules(args: &RuleArgs) -> Result<Vec<Rule>, String> {
    let mut rules = if args.no_builtin {
        Vec::new()
    } else {
        builtin_rules().map_err(|e| format!("built-in rules: {e}"))?
    };
    for path in &args.rules {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let extra = parse_rules(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        for rule in extra {
            if rules.iter().any(|existing| existing.id == rule.id) {
                return Err(format!(
                    "{}: rule id `{}` is already defined",
                    path.display(),
                    rule.id
                ));
            }
            rules.push(rule);
        }
    }
    Ok(rules)
}

fn run_list(args: RuleArgs) -> Result<ExitCode, String> {
    let rules = load_rules(&args)?;
    for rule in &rules {
        anstream::println!(
            "{:<14} {:<8} {:<9} {}",
            rule.id,
            rule.platform.as_str(),
            rule.severity,
            rule.title
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn run_audit(args: AuditArgs) -> Result<ExitCode, String> {
    let mut rules = load_rules(&args.rules)?;
    rules.retain(|rule| rule.severity >= args.min_severity);

    let ctx = match &args.root {
        Some(root) => {
            if !root.is_dir() {
                return Err(format!("--root {} is not a directory", root.display()));
            }
            Context::offline_root(root)
        }
        None => Context::host(),
    };
    if ctx.platform().is_none() {
        return Err(
            "this operating system has no rules yet; use --root to audit a Linux filesystem tree"
                .into(),
        );
    }

    let report = Report::new(&ctx, audit(&rules, &ctx));
    let rendered = match args.format {
        Format::Json => {
            let mut json = report.to_json();
            json.push('\n');
            json
        }
        Format::Text => render_text(&report, args.only_failed),
    };
    match &args.output {
        Some(path) => {
            // Strip colours: files should hold plain text.
            let plain = anstream::adapter::strip_str(&rendered).to_string();
            std::fs::write(path, plain)
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        }
        None => anstream::print!("{rendered}"),
    }

    let failed = match (args.fail_on, report.worst_failure()) {
        (FailOn::Severity(threshold), Some(worst)) => worst >= threshold,
        _ => false,
    };
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn status_label(status: Status) -> (&'static str, Style) {
    let color = |c: AnsiColor| Style::new().fg_color(Some(c.into())).bold();
    match status {
        Status::Pass => ("PASS", color(AnsiColor::Green)),
        Status::Fail => ("FAIL", color(AnsiColor::Red)),
        Status::Error => ("ERR ", color(AnsiColor::Yellow)),
        Status::NotApplicable => ("N/A ", Style::new().dimmed()),
    }
}

fn render_finding(out: &mut String, finding: &Finding) {
    let (label, style) = status_label(finding.status);
    let _ = writeln!(
        out,
        " {style}{label}{style:#}  {:<8}  {:<12}  {}",
        finding.severity, finding.id, finding.title
    );
    if finding.status == Status::Pass {
        return;
    }
    let dim = Style::new().dimmed();
    let mut note = |name: &str, text: &str| {
        let _ = writeln!(out, "         {dim}{name}:{dim:#} {text}");
    };
    if let Some(observed) = &finding.observed {
        note("observed", observed);
    }
    if finding.status == Status::Fail {
        if let Some(expected) = &finding.expected {
            note("expected", expected);
        }
    }
    if let Some(detail) = &finding.detail {
        note("detail", detail);
    }
    if finding.status == Status::Fail {
        if let Some(remediation) = &finding.remediation {
            note("fix", remediation);
        }
    }
}

fn render_text(report: &Report, only_failed: bool) -> String {
    let mut out = String::new();
    let target = match &report.offline_root {
        Some(root) => format!("offline root {root}"),
        None => "this host".to_owned(),
    };
    let _ = writeln!(
        out,
        "tabya {} · {} baseline · {target}\n",
        report.version, report.platform
    );

    for finding in &report.findings {
        let hidden = only_failed && matches!(finding.status, Status::Pass | Status::NotApplicable);
        if !hidden {
            render_finding(&mut out, finding);
        }
    }

    let summary = &report.summary;
    let _ = writeln!(
        out,
        "\n{} checks: {} passed, {} failed, {} unreadable, {} not applicable · score {}%",
        summary.total,
        summary.passed,
        summary.failed,
        summary.errors,
        summary.not_applicable,
        summary.score_percent
    );
    if summary.errors > 0 {
        let _ = writeln!(
            out,
            "Some checks could not read their target. Re-run with elevated privileges for a complete result."
        );
    }
    out
}
