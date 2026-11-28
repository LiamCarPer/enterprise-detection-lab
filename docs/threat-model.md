# Threat Model

This document describes the threats the lab is designed to detect, the telemetry it relies on, and the gaps that remain. It is an engineering tool for prioritizing detection work. It is not a compliance certification or a claim of complete ATT&CK coverage.

The model is intentionally narrow: it covers the enterprise IT telemetry in this repository and the attack paths that are represented by tested detections and investigations. Synthetic data, small samples, and the absence of production measurements remain explicit limitations.

## Scope and non-goals

### In scope

- Enterprise identity telemetry from Entra ID.
- Endpoint process, authentication, and account telemetry from Sysmon and Windows Security.
- Cloud control-plane telemetry from AWS CloudTrail.
- SaaS telemetry from Microsoft 365 audit, Exchange Online message trace, Purview DLP, ServiceNow approvals, and GitHub audit.
- Network telemetry from Zeek and Suricata.
- Kubernetes audit and Falco runtime telemetry.
- Attack paths that combine these sources into a documented sequence.

### Out of scope

- Production deployment, live response, and on-call operations.
- Operational technology, mobile, physical security, and non-IT endpoints.
- Human-resources context, insider intent, and disciplinary process.
- Full malware analysis, reverse engineering, and packet forensics.
- Claims of complete ATT&CK coverage. The matrix records what the current artifacts test, not every variant of a technique.
- Non-OpenSearch detection backends. KQL and SPL translation are planned work, not current evidence.

## Method and status vocabulary

The model uses an asset-based attack-path approach:

1. Identify the assets and trust boundaries that produce telemetry.
2. Describe the adversary profiles that would cross those boundaries.
3. Map the documented attack paths to ATT&CK techniques and repository artifacts.
4. Record coverage and gaps explicitly.
5. Feed the gap list into the detection roadmap.

Status meanings:

| Status | Meaning |
|---|---|
| **Covered** | A tested detection exercises the technique in a documented path, and a tested investigation or baseline provides supporting evidence. |
| **Partial** | A detection exists, but it covers one variant, lacks an investigation, or depends on telemetry that does not represent the full path. |
| **Gap** | The telemetry may exist, but no tested detection covers the behavior. |
| **Out of scope** | No modeled telemetry, or the behavior is outside the lab's stated scope. |

Coverage is path-specific. A `Covered` technique is covered for the chain described here, not for every possible implementation.

## System model and trust boundaries

### Assets

| Asset | Why it matters | Primary telemetry |
|---|---|---|
| Enterprise identities | Access to mail, cloud, SaaS, and administrative functions | `entra-signin`, `entra-audit` |
| Endpoints | Execution, credential access, and lateral movement | `sysmon`, `windows-security` |
| Cloud control plane | Persistence, credential creation, and logging control | `aws-cloudtrail` |
| SaaS mail and collaboration | Mail collection, forwarding, data sharing, and external delivery | `m365-audit`, `exchange-message-trace`, `m365-dlp`, `servicenow-approval` |
| Source control and CI | Organization ownership, repository access, and pipeline abuse | `github-audit` |
| Network | Command and control, tunneling, and transport evidence | `zeek`, `suricata` |
| Kubernetes workloads | Container execution, privilege, and host escape | `kubernetes-audit`, `falco` |

The source contracts, event classes, and known gaps are listed in [`docs/telemetry-matrix.md`](telemetry-matrix.md) and [`telemetry/sources/`](../telemetry/sources/).

### Trust boundaries

| Boundary | What crosses it | Telemetry | Current coverage |
|---|---|---|---|
| Internet → enterprise edge | Inbound mail, web, and network traffic | Zeek, Suricata | Partial |
| Edge → endpoint | Delivered files, scripts, and command execution | Sysmon, Windows Security | Covered for selected execution chains |
| User → identity provider | Authentication, MFA, session establishment | Entra sign-in | Covered for risky sign-in paths |
| Identity → cloud | Role assumption, access-key creation, control-plane changes | Entra audit, CloudTrail | Covered for selected persistence paths |
| Endpoint → cloud | Credential use and cloud persistence from a host | Sysmon, CloudTrail | Covered for selected chains |
| Identity → SaaS | Mailbox access, delegation, forwarding, and data sharing | Entra, Microsoft 365 audit, Exchange message trace | Covered for the mailbox takeover path |
| SaaS → external recipient | Mail delivery and data loss | Exchange message trace, Purview DLP, ServiceNow approvals | Covered for the modeled email path |
| Kubernetes control plane → workload | Pod creation, privilege, and runtime execution | Kubernetes audit, Falco | Partial |
| Repository → CI/cloud | Organization ownership, tokens, and pipeline changes | GitHub audit, CloudTrail | Partial |

## Adversary profiles

| Profile | Starting access | Objective | Likely techniques | Current coverage |
|---|---|---|---|---|
| Opportunistic external attacker | Internet-facing service or phishing | Initial access, execution, and credential theft | Phishing, malicious files, scripting, valid accounts | Partial |
| Credential and session attacker | Valid password, phished session, or stolen token | Identity persistence and cloud/SaaS access | Valid accounts, token theft, MFA abuse, account manipulation | Partial; OAuth consent, approved-application checks, session replay, impossible travel, and anomalous-token mail access are covered; token theft before detection remains a gap |
| SaaS data thief | Compromised mailbox or delegated access | Mail collection and external exfiltration | Mailbox delegation, mail access, forwarding rules, external delivery | Covered for the modeled mailbox path |
| Data-handling insider or careless user | Authorized mailbox and external recipient | Send data outside an approved boundary | External delivery, DLP policy match, approval bypass | Covered for the modeled email and DLP path |
| Cloud control-plane attacker | Cloud credentials or role assumption | Persistence, credential creation, and logging evasion | Access-key creation, account creation, logging tamper | Covered for selected paths; role and resource abuse are gaps |
| Container and Kubernetes attacker | Pod execution or compromised workload | Privilege escalation and host access | Privileged pod, container shell, host escape | Partial |
| CI/CD and supply-chain attacker | Repository or organization access | Organization takeover, secret access, pipeline abuse | Account manipulation, token theft, secret exposure | Partial; only organization owner addition is covered |

## Attack paths and current coverage

| Path | Chain | ATT&CK | Detections | Investigation | Status |
|---|---|---|---|---|---|
| Identity persistence to cloud credential access | Risky sign-in → service principal ownership → access key or logging change | T1078, T1098.002, T1098.001, T1136.003, T1562.008 | `DET-IDN-001`, `DET-IDN-002`, `DET-IDN-003`, `DET-CLD-001`, `DET-CLD-002` | [`INV-001`](../investigations/01-identity-to-cloud/) | Covered for the modeled path |
| Endpoint execution to cloud persistence | Encoded PowerShell or Office child process → cloud credential or logging change | T1059.001, T1027, T1566.001, T1204.002, T1098.001, T1562.008 | `DET-END-001`, `DET-END-002`, `DET-CLD-001`, `DET-CLD-002` | [`INV-002`](../investigations/02-endpoint-to-cloud/) | Covered for the modeled path |
| SaaS mailbox takeover | Risky sign-in → self-delegation → mail access → external forwarding → delivery → DLP | T1078, T1098, T1114.002, T1114.003, T1048.003 | `DET-SAA-001`, `DET-SAA-003`, `DET-SAA-005`, `DET-SAA-006`, `DET-SAA-007`, `DET-SAA-008` | [`INV-003`](../investigations/03-saas-mailbox-takeover/) | Covered for the modeled path |
| Denied data-sharing exception bypass | Denied or revoked approval → external delivery → DLP → quorum and authority checks | T1048.003 | `DET-SAA-008`, `DET-SAA-009` | [`INV-004`](../investigations/04-denied-external-sharing/) | Covered for the modeled path |
| OAuth consent to application access | Risky sign-in → sensitive consent with offline access → application inventory and reputation checks → application mail access | T1078, T1528, T1114.002 | `DET-IDN-001`, `DET-IDN-004`, `DET-IDN-009` | [`INV-005`](../investigations/05-oauth-consent-grant/) | Covered for the modeled path |
| Admin consent and tenant-wide grant | Admin consent → approved-application and reputation checks → tenant-wide OAuth permission grant | T1528, T1098 | `DET-IDN-005` | [`INV-006`](../investigations/06-admin-oauth-grant/) | Covered for the modeled path |
| Sensitive OAuth grant to application file access | User consent → file scope → inventory check → SharePoint file access and download | T1528, T1213.002 | `DET-IDN-010` | [`INV-010`](../investigations/10-sensitive-oauth-file-access/) | Covered for the modeled path |
| Sensitive OAuth grant to application Teams activity | User consent → Teams scope → inventory check → application message or chat activity | T1528, T1213 | `DET-IDN-011` | None | Covered for the modeled path |
| Unused sensitive OAuth grant | Sensitive grant → no application mail, file, or Teams activity in 30 days | T1528 | `DET-IDN-012` | None | Covered for the modeled review path |
| Session replay | Interactive MFA sign-in → non-interactive risky use from a new IP with the same session | T1078, T1550.001 | `DET-IDN-006` | [`INV-007`](../investigations/07-session-replay/) | Covered for the modeled path |
| Impossible travel | Interactive MFA sign-in → risky sign-in from a new country | T1078, T1550.001 | `DET-IDN-007` | [`INV-008`](../investigations/08-impossible-travel/) | Covered for the modeled path |
| Anomalous token to mail access | Long-lived, unbound anomalous-token sign-in without token protection → mailbox access | T1528, T1114.002 | `DET-IDN-008` | [`INV-009`](../investigations/09-anomalous-token-mail/) | Covered for the modeled path |
| Network tunneling and malware | DNS tunneling or high-severity network alert | T1071.004, T1071, T1105 | `DET-NET-001`, `DET-NET-002` | None | Partial |
| Kubernetes execution and privilege | Privileged pod or shell in container | T1610, T1611, T1059, T1609 | `DET-K8S-001`, `DET-K8S-002` | None | Partial |
| GitHub organization takeover | Organization owner added | T1098 | `DET-SAA-002` | None | Partial |
| Cloud role and resource abuse | Role trust change, function or resource persistence | T1098 | None | None | Gap |

`DET-END-000` is a draft reference package and is not counted as coverage.

## ATT&CK coverage matrix

The matrix records the technique mappings used by tested detections, plus the gaps that matter to the modeled paths. It does not imply that every procedure for a technique is covered.

| Tactic | Technique | Telemetry | Detections | Status | Dependency or limitation |
|---|---|---|---|---|---|
| Initial Access | T1566.001 Spearphishing Attachment | Sysmon process chain | `DET-END-002` | Partial | Observes post-attachment execution, not the mail gateway |
| Initial Access | T1078 Valid Accounts | Entra sign-in, Microsoft 365 audit | `DET-IDN-001`, `DET-IDN-003`, `DET-IDN-004`, `DET-IDN-007`, `DET-SAA-003`, `DET-SAA-004`, `DET-SAA-005`, `DET-SAA-006` | Covered for selected risky-sign-in paths | Does not detect token replay or low-risk sign-ins |
| Execution | T1059.001 PowerShell | Sysmon | `DET-END-001`, `DET-END-002` | Covered for selected parent-child chains | Living-off-the-land variants remain |
| Execution | T1204.002 Malicious File | Sysmon process chain | `DET-END-002` | Partial | No file reputation or attachment inspection |
| Execution | T1059 Command and Scripting Interpreter | Kubernetes audit, Falco | `DET-K8S-002` | Partial | Container shell only |
| Execution | T1609 Container Administration Command | Kubernetes audit, Falco | `DET-K8S-002` | Partial | No coverage of every administrative command |
| Persistence | T1098 Account Manipulation | Entra audit, Microsoft 365 audit, GitHub audit | `DET-IDN-002`, `DET-SAA-002`, `DET-SAA-004`, `DET-SAA-005`, `DET-SAA-006` | Covered for selected account changes | Role and permission variants remain |
| Persistence | T1098.001 Additional Cloud Credentials | CloudTrail | `DET-CLD-001` | Covered | Access-key creation only |
| Persistence | T1098.002 Additional Email Delegate Permissions | Microsoft 365 audit | `DET-IDN-002`, `DET-SAA-004`, `DET-SAA-005`, `DET-SAA-006` | Covered for mailbox delegation | Service principal mapping follows repository metadata |
| Persistence | T1136.003 Cloud Account | CloudTrail | `DET-CLD-001` | Covered for the modeled creation event | Other account-creation APIs remain |
| Persistence | T1114.003 Email Forwarding Rule | Microsoft 365 audit, Exchange message trace | `DET-SAA-001`, `DET-SAA-003`, `DET-SAA-006`, `DET-SAA-007` | Covered | Rule variants and mailbox-level forwarding remain partial |
| Privilege Escalation | T1078 Valid Accounts | Entra sign-in, SaaS audit | `DET-IDN-001`, `DET-IDN-003`, `DET-SAA-003`, `DET-SAA-004`, `DET-SAA-005`, `DET-SAA-006` | Covered for selected paths | Token and session abuse remain gaps |
| Privilege Escalation | T1098.002 Additional Email Delegate Permissions | Microsoft 365 audit | `DET-SAA-004`, `DET-SAA-005`, `DET-SAA-006` | Covered for mailbox delegation | Same limitation as persistence |
| Privilege Escalation | T1610 Deploy Container | Kubernetes audit | `DET-K8S-001` | Partial | Privileged pod only |
| Privilege Escalation | T1611 Escape to Host | Kubernetes audit, Falco | `DET-K8S-001` | Partial | No host-escape confirmation |
| Defense Evasion | T1562.008 Disable Cloud Logs | CloudTrail | `DET-CLD-002` | Covered | Trail and logging changes only |
| Defense Evasion | T1027 Obfuscated Files or Information | Sysmon | `DET-END-001` | Partial | Encoded command evidence, not full obfuscation analysis |
| Credential Access | T1003 OS Credential Dumping | Sysmon, Windows Security | None | Gap | No tested credential-access detection |
| Credential Access | T1528 Steal Application Access Token | Entra sign-in/audit, CloudTrail, SaaS audit | `DET-IDN-004`, `DET-IDN-005`, `DET-IDN-008`, `DET-IDN-009`, `DET-IDN-010`, `DET-IDN-011`, `DET-IDN-012` | Partial | Consent, scope, approved-application, publisher-reputation, anomalous-token, binding, age, mail-access, file-access, Teams-activity, and unused-grant paths covered; full token-issuance context remains a gap |
| Collection | T1114.002 Remote Email Collection | Microsoft 365 audit | `DET-SAA-004`, `DET-SAA-005`, `DET-SAA-006`, `DET-IDN-008`, `DET-IDN-009` | Covered for modeled paths | Mail access must follow a modeled delegation, token-risk, or sensitive OAuth grant path |
| Collection | T1213 Data from Information Repositories | Entra audit, Microsoft 365 audit | `DET-IDN-011` | Partial | Teams activity must follow a sensitive OAuth grant by the same application |
| Collection | T1213.002 Data from Information Repositories: SharePoint | Entra audit, Microsoft 365 audit | `DET-IDN-010` | Covered for modeled path | File access must follow a sensitive OAuth grant by the same application |
| Command and Control | T1071 Application Layer Protocol | Suricata | `DET-NET-002` | Partial | Signature-dependent |
| Command and Control | T1071.004 DNS | Zeek | `DET-NET-001` | Partial | Long TXT queries only |
| Exfiltration | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | Exchange message trace, Purview DLP, ServiceNow approvals | `DET-SAA-007`, `DET-SAA-008`, `DET-SAA-009` | Covered for external email | Other exfiltration channels remain gaps |
| Lateral Movement | T1021 Remote Services | Sysmon, Windows Security | None | Gap | No tested lateral-movement detection |
| Lateral Movement | T1550.001 Application Access Token | Entra sign-in/audit, CloudTrail | `DET-IDN-006`, `DET-IDN-007` | Partial | Session reuse and country change covered; token theft and other replay variants remain |
| Impact | T1486 Data Encrypted for Impact | Endpoint telemetry | None | Gap | Ransomware behavior is not modeled |

## Coverage assessment

### Strong areas

- **SaaS mail exfiltration.** The repository has a documented sequence from risky sign-in through delegation, mail access, forwarding, external delivery, and DLP confirmation. It also models approval denial, revocation, expiry, authority, renewal, and quorum.
- **Identity persistence to cloud.** The modeled chain connects risky sign-in, service principal ownership, access-key creation, and logging changes.
- **Endpoint execution to cloud.** The modeled chain connects suspicious process execution to cloud credential and logging changes.
- **Data-handling exception bypass.** The repository distinguishes an approved transfer from a denied or revoked request that was bypassed, including a DLP match.
- **OAuth consent to application access.** The modeled chain connects a risky sign-in, a sensitive consent with offline access, an approved-application and publisher-reputation check, and application mail access.
- **Sensitive OAuth grant to application file access.** The modeled chain connects a sensitive file consent, an approved-application check, and application file access and download from SharePoint.
- **Sensitive OAuth grant to application Teams activity.** The modeled chain connects a sensitive Teams consent, an approved-application check, and application message or chat activity.
- **Unused sensitive OAuth grant.** The review path identifies a sensitive grant with no observed application mail, file, or Teams activity in 30 days.
- **Admin and tenant-wide OAuth grants.** The modeled chain connects admin consent and tenant-wide grants to approved-application, publisher-verification, redirect-trust, and publisher-reputation checks.
- **Session replay.** The modeled chain connects an interactive MFA sign-in to non-interactive risky use of the same session from a different IP.
- **Impossible travel.** The modeled chain connects an interactive MFA sign-in to a risky sign-in from a different country.
- **Anomalous token to mail access.** The modeled chain connects a long-lived anomalous-token risk on an unprotected, unbound sign-in to mailbox access.

### Thin areas

- **Network.** Two detections cover DNS tunneling and high-severity alerts, but there is no investigation and no packet-level evidence.
- **Kubernetes.** Two detections cover privileged pods and container shells, but there is no investigation, RBAC coverage, or host-escape confirmation.
- **GitHub.** One detection covers organization owner addition. Repository secrets, token abuse, and pipeline changes are not covered.
- **Windows Security.** The source is ingested, but there is no tested detection dedicated to Windows authentication or account-management events.

### Prioritized gaps

| Gap | Why it matters | Telemetry available | Missing | Priority |
|---|---|---|---|---|
| Token and session theft | Bypasses password and MFA controls and enables replay | Entra sign-in/audit, CloudTrail, SaaS audit | Full token-issuance context and cross-service token correlation | High |
| OAuth access-review operations | Unused-grant discovery is covered, but owner context, business justification, review workflow, and stale-inventory refresh remain operational gaps | Entra audit, Microsoft 365 audit, tenant configuration | Review workflow and owner context | Medium |
| Cloud role and resource persistence | Persistence beyond access keys and logging changes | CloudTrail | Role trust, function, and resource-change detections | High |
| Endpoint credential access and lateral movement | Common path to ransomware and domain compromise | Sysmon, Windows Security | Credential-dumping and remote-service detections | High |
| Kubernetes RBAC and host escape | Cluster compromise and container escape | Kubernetes audit, Falco | RBAC-abuse detection and host-escape investigation | High |
| CI/CD and GitHub secret exposure | Supply-chain access and organization takeover | GitHub audit | Secret, token, and pipeline-change detections | Medium |
| Non-mail exfiltration | Data can leave through Teams, SharePoint, personal cloud, DNS, or HTTP | Microsoft 365 audit, Zeek, Suricata | Cross-channel exfiltration correlation | Medium |
| Windows Security depth | Authentication and account changes are under-covered | Windows Security | Tested detections and an investigation | Medium |

## Assumptions, evasion, and failure modes

### Telemetry assumptions

- Logs are delivered and retained long enough for correlation.
- Source clocks are close enough for the configured windows.
- Microsoft 365 accepted domains correctly distinguish internal from external recipients.
- Exchange message trace includes the detail fields used by the detections.
- DLP alerts include the message identifier and content scope used by the correlation.
- ServiceNow approvals include approval group, authority, expiry, and quorum-relevant fields.
- Kubernetes audit and Falco events describe the same workload and time window.

### Detection assumptions

- A message identifier remains stable across transport and DLP records.
- A content scope is meaningful and stable enough to distinguish datasets.
- A valid delegate chain is resolved into `authority: primary` before correlation.
- A quorum is represented by distinct approvers in the same approval group.
- An approval that expires before the last required event is not authoritative.

### Evasion and blind spots

- Low-and-slow activity below correlation windows.
- Approved exceptions that are broader than the actual sharing decision.
- Compromised or colluding approvers.
- Alternate exfiltration channels such as Teams, SharePoint, personal cloud, DNS, or HTTP.
- Living-off-the-land execution that does not match the modeled parent-child chains.
- Logging tampering outside the modeled CloudTrail actions.
- Encrypted command and control that does not trigger a signature.
- Container activity that does not create a privileged pod or an interactive shell.

### Failure modes

- Missing telemetry produces false negatives without a visible error.
- Broad DLP or approval records can suppress an alert incorrectly.
- Single-source detections can produce volume without enough context.
- Synthetic fixtures demonstrate logic, not production precision, recall, or latency.
- A coverage table can become stale if it is not updated with new detections and investigations.

## Roadmap and maintenance

### Next detection candidates

1. Full token issuance context and token-protection policy coverage across Entra sign-in and cloud/SaaS activity.
2. Cloud role trust and resource-persistence detection.
3. Endpoint credential access and remote-service detection.
4. Kubernetes RBAC escalation detection.
5. GitHub secret and token abuse detection.
6. Cross-channel external sharing detection for Teams and SharePoint.

### Next investigations

1. Network tunneling and malware alert to external infrastructure.
2. Kubernetes privileged pod to host access.
3. GitHub organization takeover or secret exposure.
4. Token theft to cloud or SaaS access.

### Maintenance triggers

Review this document when any of the following changes:

- A telemetry source or event class is added or retired.
- A tested detection is added, retired, or materially retuned.
- A tested investigation is added or its evidence changes.
- A new attack path is demonstrated in the lab.
- An exception or suppression rule changes the expected behavior.

Owner: detection engineering. Review cadence: quarterly, and on any material change to the detection or telemetry corpus.

### Rule for new work

Every new detection should map to an attack path or ATT&CK technique in this document. If it does not, the package should record why the behavior is still worth detecting. This keeps the threat model connected to the corpus instead of becoming a standalone essay.

## References

- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [`docs/artifact-model.md`](artifact-model.md)
- [`docs/detection-testing.md`](detection-testing.md)
- [`docs/telemetry-matrix.md`](telemetry-matrix.md)
- [`docs/capability-matrix.md`](capability-matrix.md)
- [`docs/requirements-traceability.md`](requirements-traceability.md)
- [`reports/detection-metrics.md`](../reports/detection-metrics.md)
- [`reports/benign-baseline-results.md`](../reports/benign-baseline-results.md)
