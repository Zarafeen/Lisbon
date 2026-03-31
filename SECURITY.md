# Security Policy

## Supported Status

Lisbon is currently a beta open-source project for personal Windows use. Security-related fixes are welcome, but there is no formal enterprise support policy.

## Reporting a Vulnerability

Please do not open a public issue for a sensitive vulnerability right away.

Instead, report it privately to the maintainer through GitHub security reporting if enabled, or by direct maintainer contact if one is published on the repository profile.

When reporting, include:

- affected file or module
- reproduction steps
- expected impact
- whether the issue requires admin privileges
- whether it can modify, expose, or destroy user data

## Scope Notes

Security-sensitive areas in this project include:

- command execution helpers
- auto-fix routines
- quarantine and file movement logic
- PowerShell and Windows registry interactions
- malware scanning rules and false-positive handling

## Safe Defaults

The project should prefer:

- non-destructive defaults
- explicit opt-in for risky actions
- quarantine over deletion
- strong logging for remediation steps
- conservative automation when detections are low confidence
