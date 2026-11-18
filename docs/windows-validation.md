# Windows 11 validation log

This file records runs of the built-in Windows 11 baseline on real machines.
It states what was observed, not what is assumed.

## 2026-11-19 — tabya 0.1.0, first run on a real machine

| | |
| --- | --- |
| Binary | `tabya.exe` 0.1.0, cross-compiled from Linux for `x86_64-pc-windows-gnu` |
| Host | One personal Windows 11 desktop, OS version `10.0.26300` |
| Result | 22 checks: 15 pass, 7 fail, 0 unreadable, 0 not applicable. Score 68%. |

### What this run shows

- The cross-compiled binary starts and completes on Windows 11.
- All 22 registry checks returned a verdict; none failed to read.

### What it does not show

- It is one machine and one OS build. Other editions, domain-joined hosts and
  older builds are untested.
- Nothing was compared against an independent tool, so a "pass" or "fail" here
  is tabya's reading of the registry, not a confirmed assessment.
- The Windows CI job has not run yet.

### Failed checks

| Rule | Observed | Note |
| --- | --- | --- |
| `WIN-LSA-003` | `LmCompatibilityLevel` not set, default 3 assumed | Rule expects 5 or higher. |
| `WIN-UAC-002` | `ConsentPromptBehaviorAdmin` = 5 | Windows default; rule expects 1 or 2. |
| `WIN-SMB-002` | `RequireSecuritySignature` (server) not set, default 0 assumed | See open question below. |
| `WIN-SMB-003` | `RequireSecuritySignature` (client) not set, default 0 assumed | See open question below. |
| `WIN-PS-001` | Script block logging policy absent | |
| `WIN-NET-001` | `EnableMulticast` not set, default 1 assumed | LLMNR left enabled. |
| `WIN-AUTO-001` | `NoDriveTypeAutoRun` not set, default 145 assumed | |

### Open question: SMB signing default

`WIN-SMB-002` and `WIN-SMB-003` assume signing is **not** required when the
registry value is absent. Recent Windows 11 releases changed the SMB signing
defaults, so on such a build the two failures above may be false positives.
This has not been checked yet. The plan is to compare against
`Get-SmbServerConfiguration` and `Get-SmbClientConfiguration` on the same
host, then either make the default version-aware or read the effective
configuration instead of the raw registry value.
