# Runbook — Reference Detection

This is a reference artifact used by `edl new detection`. It is not a production detection.

## Triage

1. Confirm the process is `whoami.exe`.
2. Check the parent process and command line.
3. Correlate with discovery activity on the same host.
4. Check whether the user is an administrator or a service account.

## Evidence

- Sysmon Event ID 1.
- `UtcTime`, `Computer`, `Image`, `CommandLine`, and parent fields.

## Escalation

Escalate if the command is part of a broader discovery or lateral-movement sequence.

## Containment

No automatic containment. Follow the host isolation runbook if the host is confirmed compromised.

## False positives

Administrative discovery and provisioning scripts.
