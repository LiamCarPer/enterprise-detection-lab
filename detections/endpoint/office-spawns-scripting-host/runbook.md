# Runbook — Office Application Spawns Scripting Host

## Alert meaning

A Microsoft Office application created PowerShell, cmd, Windows Script Host, cscript, or mshta. This behavior is common in malicious documents and macros, but can also come from approved add-ins or document workflows.

## Triage

1. Identify the Office application, child process, command line, user, and host.
2. Review the parent document path and whether it came from email, a download, or a shared drive.
3. Inspect the child command line for download, execution, persistence, or discovery behavior.
4. Check the process tree for additional children and network connections.
5. Review recent file creation, registry changes, and scheduled tasks on the host.
6. Confirm whether the user has an approved macro or add-in workflow.

## Evidence

- `host`, `user`, `event_time`, and `process.guid`
- Office parent image and command line
- Child image, command line, and process ID
- Document path and hash when available
- Network connections, file writes, and registry activity
- User confirmation and business context

## Escalation

Escalate when:

- The document came from an external sender or untrusted download.
- The child process downloads or executes remote content.
- The user did not expect the document to run scripts.
- The same document or command appears on multiple hosts.
- The host has privileged access or sensitive data.

## Containment

- Isolate the host if execution is confirmed malicious.
- Preserve the document, process tree, command lines, and network evidence.
- Terminate the process tree after evidence capture.
- Remove the document and any dropped payloads.
- Reset credentials if the child process accessed credentials or tokens.

## False positives

- Approved macros or add-ins that launch scripts.
- Document management or e-discovery tools that wrap Office.
- Security testing and controlled malware analysis.
- Vendor templates with signed, documented automation.

## Closure

Record the document source and hash, parent and child command lines, user confirmation, related endpoint activity, containment, and any allow-list decision. Allow-list only a specific signed document or add-in workflow, not an entire Office application.

## References

- Microsoft Sysmon Event ID 1 — Process creation
- MITRE ATT&CK T1566.001 — Spearphishing Attachment
- MITRE ATT&CK T1204.002 — Malicious File
- MITRE ATT&CK T1059.001 — PowerShell
