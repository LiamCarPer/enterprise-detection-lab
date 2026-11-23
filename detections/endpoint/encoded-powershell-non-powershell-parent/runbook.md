# Runbook — Encoded PowerShell From Non-PowerShell Parent

## Alert meaning

A PowerShell or pwsh process executed an encoded command, and the parent is not another PowerShell host. Encoded commands hide the script text and are common in phishing, commodity malware, and administrative automation.

## Triage

1. Identify the parent process, command line, user, host, and process GUID.
2. Decode the command in an isolated environment or with a local decoder. Never execute decoded content on a production host.
3. Check whether the parent is a known management tool, installer, Office application, browser, or script host.
4. Review the process tree and recent child processes on the host.
5. Check for network connections, file writes, registry changes, and scheduled tasks around the event.
6. Compare the command with approved administrative scripts and deployment jobs.

## Evidence

- `host`, `user`, `event_time`, `event_code`, and `process.guid`
- `process.image`, `process.command_line`, `process.parent_name`, and `process.parent_command_line`
- Decoded command text, with a hash of the original command
- Child processes, network connections, file and registry activity
- User logon context and endpoint management status

## Escalation

Escalate when:

- The parent is Office, a browser, a script host, or an unknown executable.
- The decoded command downloads content, disables security controls, or touches credentials.
- The user did not initiate the activity.
- The same command appears on multiple hosts.
- The host has privileged access or sensitive data.

## Containment

- Isolate the host if execution is confirmed malicious.
- Preserve process, command-line, network, and file evidence.
- Terminate the process tree only after evidence capture.
- Reset credentials used in the session if credential access is suspected.
- Remove persistence and block known command-and-control infrastructure.

## False positives

- Approved administrative scripts launched from a management shell.
- Software deployment tools that use encoded PowerShell.
- Security testing and detection validation.
- Vendor installers that wrap PowerShell commands.

## Closure

Record the decoded command, parent process, user intent, related endpoint activity, containment actions, and any tuning. Add a documented allow-list only for a specific parent, command hash, and business workflow.

## References

- Microsoft Sysmon Event ID 1 — Process creation
- MITRE ATT&CK T1059.001 — PowerShell
- MITRE ATT&CK T1027 — Obfuscated Files or Information
