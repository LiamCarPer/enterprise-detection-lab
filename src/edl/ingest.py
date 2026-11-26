"""Normalize telemetry and ingest it into OpenSearch."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from . import config
from .errors import IngestError
from .telemetry import TelemetrySource, load_sources
from .tenant import accepted_mail_domains
from .utils import read_json, sha256_file

Normalizer = Callable[[Mapping[str, Any]], dict[str, Any]]
Classifier = Callable[[Mapping[str, Any]], str]

IDENTITY_SOURCES: tuple[str, ...] = ("entra-signin", "entra-audit")
ENDPOINT_SOURCES: tuple[str, ...] = ("sysmon", "windows-security")
CLOUD_SOURCES: tuple[str, ...] = ("aws-cloudtrail",)
SAAS_SOURCES: tuple[str, ...] = (
    "m365-audit",
    "github-audit",
    "exchange-message-trace",
    "m365-dlp",
    "servicenow-approval",
)
NETWORK_SOURCES: tuple[str, ...] = ("zeek", "suricata")
KUBERNETES_SOURCES: tuple[str, ...] = ("kubernetes-audit", "falco")
DOMAIN_SOURCES: dict[str, tuple[str, ...]] = {
    "identity": IDENTITY_SOURCES,
    "endpoint": ENDPOINT_SOURCES,
    "cloud": CLOUD_SOURCES,
    "saas": SAAS_SOURCES,
    "network": NETWORK_SOURCES,
    "kubernetes": KUBERNETES_SOURCES,
}


@dataclass(frozen=True)
class CanonicalEvent:
    """One validated event ready to be written to OpenSearch."""

    source: str
    event_class: str
    event_time: datetime
    ingest_time: datetime
    document: dict[str, Any]
    dedup_id: str


@dataclass(frozen=True)
class IngestResult:
    """Outcome of one source ingest."""

    source: str
    dataset: Path
    read: int
    unique: int
    duplicates: int
    indices: tuple[str, ...]
    written: int
    counts: dict[str, int]
    dry_run: bool

    @property
    def mode(self) -> str:
        return "dry-run" if self.dry_run else "ingested"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "dataset": str(self.dataset),
            "read": self.read,
            "unique": self.unique,
            "duplicates": self.duplicates,
            "indices": list(self.indices),
            "written": self.written,
            "counts": self.counts,
            "dry_run": self.dry_run,
            "mode": self.mode,
        }


def parse_timestamp(value: Any, *, source: str, field: str) -> datetime:
    """Parse an ISO 8601 timestamp or epoch seconds and normalize it to UTC."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise IngestError(f"{source}: invalid {field}: {value!r}") from exc
    if not isinstance(value, str) or not value:
        raise IngestError(f"{source}: {field} must be a non-empty ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IngestError(f"{source}: invalid {field}: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IngestError(f"{source}: naive {field} is not allowed: {value!r}")
    return parsed.astimezone(UTC)


def format_timestamp(value: datetime) -> str:
    """Render a timestamp as UTC ISO 8601 with a Z suffix."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _lookup(data: Mapping[str, Any], dotted: str) -> Any:
    if dotted in data:
        return data[dotted]
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _present(value: Any) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def _compact(values: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if _present(value)}


def _meaningful(value: Any) -> Any:
    """Drop placeholders used by Windows event exports."""
    if value is None or value == "" or value == "-":
        return None
    return value


def _normalize_result(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized in {"success", "succeeded", "true"}:
        return "success"
    if normalized in {"failure", "failed", "false"}:
        return "failure"
    return normalized or None


def _recipient_list(value: Any) -> list[str]:
    """Expand a recipient value into individual address strings."""
    if isinstance(value, str):
        return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    if isinstance(value, list):
        recipients: list[str] = []
        for item in value:
            recipients.extend(_recipient_list(item))
        return recipients
    if isinstance(value, Mapping):
        for key in ("Address", "EmailAddress", "Value"):
            if key in value:
                return _recipient_list(value[key])
    return []


def _recipient_domain(recipient: str) -> str | None:
    """Return the lowercased domain from one forwarding recipient."""
    candidate = recipient.strip()
    if "@" not in candidate:
        return None
    domain = candidate.rsplit("@", 1)[1].strip().rstrip(">").lower()
    return domain or None


def _m365_parameter_items(raw: Mapping[str, Any]) -> list[tuple[str, Any]]:
    """Return name/value pairs from Parameters and OperationProperties."""
    items: list[tuple[str, Any]] = []
    for key in ("Parameters", "OperationProperties"):
        values = raw.get(key)
        if isinstance(values, Mapping):
            for name, value in values.items():
                items.append((str(name), value))
        elif isinstance(values, list):
            for item in values:
                if not isinstance(item, Mapping):
                    continue
                name = item.get("Name")
                if isinstance(name, str):
                    items.append((name, item.get("Value")))
    return items


FORWARD_PARAMETER_NAMES = frozenset(
    {
        "ForwardTo",
        "RedirectTo",
        "ForwardAsAttachmentTo",
        "ForwardToRecipients",
        "RedirectToRecipients",
        "ForwardAsAttachmentToRecipients",
        "ForwardToRecipientsAction",
        "RedirectToRecipientsAction",
        "ForwardAsAttachmentToRecipientsAction",
    }
)


def _m365_forward_recipients(raw: Mapping[str, Any]) -> list[str]:
    """Collect every forwarding recipient from inbox-rule audit parameters."""
    recipients: list[str] = []
    for name, value in _m365_parameter_items(raw):
        if name not in FORWARD_PARAMETER_NAMES:
            continue
        for recipient in _recipient_list(value):
            if recipient not in recipients:
                recipients.append(recipient)
    return recipients


def _access_rights(value: Any) -> list[str]:
    """Expand an Exchange access-rights value into individual rights."""
    if isinstance(value, str):
        return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    if isinstance(value, list):
        rights: list[str] = []
        for item in value:
            rights.extend(_access_rights(item))
        return rights
    return []


def _m365_parameters(raw: Mapping[str, Any]) -> dict[str, Any]:
    return dict(_m365_parameter_items(raw))


def _basename(value: Any) -> str | None:
    """Return a lowercase executable basename for either path separator."""
    if not isinstance(value, str) or not value:
        return None
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _event_id(raw: Mapping[str, Any]) -> int | None:
    value = raw.get("EventID")
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


SYSMON_EVENT_CLASSES: dict[int, str] = {
    1: "process_creation",
    3: "network_connection",
    10: "process_access",
    11: "file_create",
    12: "registry_set",
    13: "registry_set",
    14: "registry_set",
    22: "dns_query",
}

WINDOWS_AUTHENTICATION_EVENT_IDS: frozenset[int] = frozenset(
    {4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4776}
)
WINDOWS_ACCOUNT_MANAGEMENT_EVENT_IDS: frozenset[int] = frozenset(
    {
        4720,
        4722,
        4723,
        4724,
        4725,
        4726,
        4728,
        4732,
        4738,
        4740,
        4756,
        4767,
    }
)

WINDOWS_ACTIONS: dict[int, str] = {
    4624: "logon",
    4625: "logon_failure",
    4634: "logoff",
    4647: "user_initiated_logoff",
    4648: "explicit_credential_logon",
    4672: "special_privileges_assigned",
    4720: "user_created",
    4722: "user_enabled",
    4723: "password_change_attempt",
    4724: "password_reset",
    4725: "user_disabled",
    4726: "user_deleted",
    4728: "member_added_to_global_group",
    4732: "member_added_to_local_group",
    4738: "user_changed",
    4740: "user_locked",
    4756: "member_added_to_universal_group",
    4767: "user_unlocked",
    4768: "kerberos_tgt_requested",
    4769: "kerberos_service_ticket_requested",
    4776: "ntlm_authentication",
}


def classify_sysmon(raw: Mapping[str, Any]) -> str:
    """Map a Sysmon EventID to a declared event class."""
    event_id = _event_id(raw)
    if event_id is None:
        return "other"
    return SYSMON_EVENT_CLASSES.get(event_id, "other")


def classify_windows_security(raw: Mapping[str, Any]) -> str:
    """Map a Windows Security EventID to a declared event class."""
    event_id = _event_id(raw)
    if event_id in WINDOWS_AUTHENTICATION_EVENT_IDS:
        return "authentication"
    if event_id in WINDOWS_ACCOUNT_MANAGEMENT_EVENT_IDS:
        return "account_management"
    return "other"


def classify_m365_audit(raw: Mapping[str, Any]) -> str:
    """Map an M365 operation or workload to the declared event class."""
    operation = str(raw.get("Operation", ""))
    if operation in {
        "Add-MailboxPermission",
        "Add-MailboxFolderPermission",
        "Add-DistributionGroupMember",
        "Add-UnifiedGroupLinks",
        "Remove-MailboxPermission",
        "Remove-MailboxFolderPermission",
        "Remove-DistributionGroupMember",
        "Remove-UnifiedGroupLinks",
    }:
        return "mailbox_permission"
    if operation == "MailItemsAccessed":
        return "mail_access"
    workload = str(raw.get("Workload", "")).lower()
    if "exchange" in workload:
        return "mailbox"
    if "sharepoint" in workload or "onedrive" in workload:
        return "sharepoint"
    if "teams" in workload:
        return "teams"
    return "audit"


def classify_github_audit(raw: Mapping[str, Any]) -> str:
    """Map a GitHub audit action to the declared event class."""
    action = str(raw.get("action", ""))
    if action.startswith("git."):
        return "git"
    if action in {"user.login", "user.failed_login"}:
        return "authentication"
    return "audit_log"


EXCHANGE_MESSAGE_TRACE_EVENT_CLASSES: frozenset[str] = frozenset(
    {
        "deliver",
        "forward",
        "redirect",
        "send",
        "receive",
        "fail",
        "defer",
        "expand",
        "transfer",
        "resolve",
    }
)

EXCHANGE_MESSAGE_TRACE_SUCCESS_EVENTS: frozenset[str] = frozenset(
    {
        "deliver",
        "forward",
        "redirect",
        "send",
        "receive",
        "expand",
        "transfer",
        "resolve",
    }
)


def classify_exchange_message_trace(raw: Mapping[str, Any]) -> str:
    """Map an Exchange message trace Event to the declared event class."""
    event = raw.get("Event")
    normalized = event.strip().lower() if isinstance(event, str) else ""
    if normalized in EXCHANGE_MESSAGE_TRACE_EVENT_CLASSES:
        return normalized
    return "other"


def classify_zeek(raw: Mapping[str, Any]) -> str:
    """Map a Zeek log path to the declared event class."""
    path = str(raw.get("_path", "")).lower()
    if path in {"conn", "dns", "http", "ssl", "files"}:
        return path
    return "other"


def classify_suricata(raw: Mapping[str, Any]) -> str:
    """Map a Suricata EVE event type to the declared event class."""
    event_type = str(raw.get("event_type", "")).lower()
    if event_type in {"alert", "flow", "dns", "http", "tls"}:
        return event_type
    return "other"


def normalize_entra_signin(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map Entra sign-in fields to the canonical identity shape."""
    document: dict[str, Any] = {
        "action": "sign_in",
        "event_id": raw.get("id"),
        "user": raw.get("userPrincipalName"),
        "src_ip": raw.get("ipAddress"),
        "app": raw.get("appDisplayName"),
        "result": raw.get("status"),
        "auth_requirement": raw.get("authenticationRequirement"),
        "is_interactive": raw.get("isInteractive"),
        "conditional_access_status": raw.get("conditionalAccessStatus"),
        "risk_level": raw.get("riskLevelDuringSignIn"),
        "session_id": raw.get("sessionId"),
    }

    device = raw.get("deviceDetail")
    if isinstance(device, Mapping):
        detail = _compact(
            {
                "os": device.get("operatingSystem"),
                "browser": device.get("browser"),
                "id": device.get("deviceId"),
            }
        )
        if detail:
            document["device"] = detail
    return _compact(document)


def normalize_entra_audit(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map Entra audit fields to the canonical identity shape."""
    user: Any = None
    app: Any = None
    src_ip: Any = None

    initiated_by = raw.get("initiatedBy")
    if isinstance(initiated_by, Mapping):
        user_data = initiated_by.get("user")
        if isinstance(user_data, Mapping):
            user = user_data.get("userPrincipalName") or user_data.get("displayName")
            src_ip = user_data.get("ipAddress")
        app_data = initiated_by.get("app")
        if isinstance(app_data, Mapping):
            app = app_data.get("displayName")
            if user is None:
                user = app

    document: dict[str, Any] = {
        "action": raw.get("operationName"),
        "event_id": raw.get("id"),
        "user": user,
        "app": app,
        "src_ip": src_ip,
        "result": raw.get("result"),
    }

    targets = raw.get("targetResources")
    if isinstance(targets, list) and targets:
        first = targets[0]
        if isinstance(first, Mapping):
            resource = _compact(
                {
                    "name": first.get("displayName"),
                    "type": first.get("type"),
                }
            )
            resource["count"] = len(targets)
            document["resource"] = resource

            consent_type = first.get("consentType")
            document["consent_type"] = (
                consent_type.lower() if isinstance(consent_type, str) else consent_type
            )
            raw_scopes = first.get("scopes")
            scopes: list[str] = []
            if isinstance(raw_scopes, list):
                scopes = sorted(
                    {scope.lower() for scope in raw_scopes if isinstance(scope, str) and scope}
                )
            elif isinstance(raw_scopes, str):
                scopes = sorted(
                    {scope.lower() for scope in raw_scopes.replace(",", " ").split() if scope}
                )
            if scopes:
                document["scopes"] = scopes
                document["offline_access"] = "offline_access" in scopes
            document["app_owner_organization_id"] = first.get("appOwnerOrganizationId")
            document["publisher_verified"] = first.get("publisherVerified")
            document["redirect_uri_trusted"] = first.get("redirectUriTrusted")
            document["redirect_uri"] = first.get("redirectUri")
            document["tenant_wide"] = first.get("tenantWide")
    return _compact(document)


NORMALIZERS: dict[str, Normalizer] = {
    "entra-signin": normalize_entra_signin,
    "entra-audit": normalize_entra_audit,
}


def normalize_sysmon(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map Sysmon fields to the canonical endpoint shape."""
    document: dict[str, Any] = {
        "host": raw.get("Computer"),
        "user": raw.get("User"),
        "event_code": _event_id(raw),
    }

    process = _compact(
        {
            "name": _basename(raw.get("Image")),
            "image": raw.get("Image"),
            "command_line": raw.get("CommandLine"),
            "guid": raw.get("ProcessGuid"),
            "id": raw.get("ProcessId"),
            "parent_name": _basename(raw.get("ParentImage")),
            "parent_image": raw.get("ParentImage"),
            "parent_command_line": raw.get("ParentCommandLine"),
        }
    )
    if process:
        document["process"] = process

    network = _compact(
        {
            "source_ip": raw.get("SourceIp"),
            "source_port": raw.get("SourcePort"),
            "destination_ip": raw.get("DestinationIp"),
            "destination_port": raw.get("DestinationPort"),
            "protocol": raw.get("Protocol"),
        }
    )
    if network:
        document["network"] = network

    file_fields = _compact({"target_filename": raw.get("TargetFilename")})
    if file_fields:
        document["file"] = file_fields

    registry = _compact(
        {
            "target_object": raw.get("TargetObject"),
            "details": raw.get("Details"),
        }
    )
    if registry:
        document["registry"] = registry

    dns = _compact(
        {
            "query_name": raw.get("QueryName"),
            "query_results": raw.get("QueryResults"),
        }
    )
    if dns:
        document["dns"] = dns

    return _compact(document)


def normalize_windows_security(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map Windows Security fields to the canonical endpoint shape."""
    event_id = _event_id(raw)
    if event_id == 4624:
        result = "success"
    elif event_id == 4625:
        result = "failure"
    else:
        result = None

    document: dict[str, Any] = {
        "host": raw.get("Computer"),
        "user": _meaningful(raw.get("TargetUserName")),
        "event_code": event_id,
        "action": WINDOWS_ACTIONS.get(event_id) if event_id is not None else None,
        "result": result,
        "src_ip": _meaningful(raw.get("IpAddress")),
        "logon_type": raw.get("LogonType"),
        "status": _meaningful(raw.get("Status")),
        "subject_user": _meaningful(raw.get("SubjectUserName")),
        "service_name": _meaningful(raw.get("ServiceName")),
        "task_name": _meaningful(raw.get("TaskName")),
    }
    return _compact(document)


def normalize_aws_cloudtrail(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map AWS CloudTrail fields to the canonical cloud shape."""
    identity = raw.get("userIdentity")
    identity_type: Any = None
    identity_arn: Any = None
    if isinstance(identity, Mapping):
        identity_type = identity.get("type")
        identity_arn = identity.get("arn") or identity.get("principalId")

    error_code = _meaningful(raw.get("errorCode"))
    document: dict[str, Any] = {
        "user": identity_arn,
        "src_ip": _meaningful(raw.get("sourceIPAddress")),
        "action": raw.get("eventName"),
        "result": "failure" if error_code else "success",
        "service": raw.get("eventSource"),
        "account": raw.get("recipientAccountId"),
        "region": raw.get("awsRegion"),
        "event_id": raw.get("eventID"),
        "identity_type": identity_type,
        "identity_arn": identity_arn,
        "error_code": error_code,
        "user_agent": _meaningful(raw.get("userAgent")),
    }
    return _compact(document)


def normalize_m365_audit(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map Microsoft 365 unified audit fields to the canonical SaaS shape."""
    parameters = _m365_parameters(raw)
    record_type = raw.get("RecordType")
    recipients = _m365_forward_recipients(raw)
    domains = sorted(
        {domain for recipient in recipients if (domain := _recipient_domain(recipient)) is not None}
    )
    accepted = accepted_mail_domains()
    forward_external = any(domain not in accepted for domain in domains) if domains else None
    identity = _meaningful(parameters.get("Identity") or parameters.get("Mailbox"))
    folder = _meaningful(parameters.get("FolderName"))
    operation = str(raw.get("Operation", ""))
    group: Any = None
    group_member: Any = None
    mailbox = identity
    if operation in {"Add-DistributionGroupMember", "Add-UnifiedGroupLinks"}:
        group = identity
        group_member = _meaningful(parameters.get("Member") or parameters.get("Links"))
        mailbox = None
    elif isinstance(identity, str) and ":" in identity:
        mailbox_part, folder_part = identity.split(":", 1)
        mailbox = mailbox_part.strip() or identity
        if folder is None:
            folder = folder_part.strip().lstrip("\\/") or None
    if not mailbox and operation in {
        "MailItemsAccessed",
        "New-InboxRule",
        "Set-InboxRule",
        "UpdateInboxRules",
    }:
        object_id = _meaningful(raw.get("ObjectId"))
        if isinstance(object_id, str):
            mailbox_part, _, folder_part = object_id.partition("\\")
            mailbox = mailbox_part.strip() or None
            if folder is None and folder_part:
                folder = folder_part.strip() or None
    delegate = _meaningful(parameters.get("User") or parameters.get("Member"))
    user = raw.get("UserId")
    self_delegation: bool | None = None
    if isinstance(delegate, str) and isinstance(user, str) and delegate and user:
        self_delegation = delegate.lower() == user.lower()
    document: dict[str, Any] = {
        "event_id": raw.get("Id"),
        "user": raw.get("UserId"),
        "src_ip": _meaningful(raw.get("ClientIP")),
        "action": raw.get("Operation"),
        "result": _normalize_result(raw.get("ResultStatus")),
        "workload": raw.get("Workload"),
        "record_type": str(record_type) if record_type is not None else None,
        "object_id": raw.get("ObjectId"),
        "rule_name": _meaningful(parameters.get("Name")),
        "forward_to": recipients[0] if recipients else None,
        "forward_domain": _recipient_domain(recipients[0]) if recipients else None,
        "forward_domains": domains,
        "forward_external": forward_external,
        "delivery_recipient": recipients[0].lower() if recipients else None,
        "delivery_recipients": sorted({recipient.lower() for recipient in recipients}),
        "mailbox": mailbox,
        "folder": folder,
        "group": group,
        "group_member": group_member,
        "delegate": delegate,
        "self_delegation": self_delegation,
        "access_rights": _access_rights(parameters.get("AccessRights")),
    }
    return _compact(document)


def normalize_github_audit(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map GitHub organization audit fields to the canonical SaaS shape."""
    status = raw.get("status") or raw.get("result")
    role = raw.get("permission") or raw.get("role")
    document: dict[str, Any] = {
        "event_id": raw.get("id"),
        "user": raw.get("actor"),
        "src_ip": _meaningful(raw.get("actor_ip")),
        "action": raw.get("action"),
        "result": _normalize_result(status) or "success",
        "service": "github",
        "organization": raw.get("org"),
        "repository": raw.get("repo"),
        "target_user": raw.get("user"),
        "role": str(role).lower() if role is not None else None,
        "user_agent": _meaningful(raw.get("user_agent")),
    }
    return _compact(document)


def normalize_m365_dlp(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map a Purview DLP alert to the canonical SaaS shape."""
    status = raw.get("Status")
    severity = raw.get("Severity")
    message_id = raw.get("MessageId")
    recipient = raw.get("Recipient")
    content_scope = raw.get("ContentScope")
    document: dict[str, Any] = {
        "event_id": raw.get("AlertId"),
        "user": raw.get("User"),
        "action": raw.get("PolicyName"),
        "status": str(status).lower() if status is not None else None,
        "severity": str(severity).lower() if severity is not None else None,
        "policy_name": raw.get("PolicyName"),
        "recipient": recipient,
        "subject": raw.get("Subject"),
        "message_id": message_id.lower() if isinstance(message_id, str) else message_id,
        "workload": raw.get("Workload"),
        "detection_method": raw.get("DetectionMethod"),
        "dlp_action": raw.get("Action"),
        "delivery_recipient": recipient.lower() if isinstance(recipient, str) else recipient,
        "content_scope": (
            content_scope.lower() if isinstance(content_scope, str) else content_scope
        ),
        "service": "purview-dlp",
    }
    return _compact(document)


def normalize_servicenow_approval(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map a ServiceNow approval decision to the canonical SaaS shape."""
    mailbox = raw.get("requested_for")
    recipient = raw.get("recipient")
    message_id = raw.get("message_id")
    state = raw.get("state")
    approval = raw.get("approval")
    content_scope = raw.get("content_scope")
    expires_on = raw.get("expires_on")
    approver_role = raw.get("approver_role")
    authority = raw.get("authority")
    document: dict[str, Any] = {
        "event_id": raw.get("sys_id"),
        "request_number": raw.get("number"),
        "requested_by": raw.get("requested_by"),
        "approver": raw.get("approver"),
        "status": str(state).lower() if state is not None else None,
        "decision": str(approval).lower() if approval is not None else None,
        "mailbox": mailbox.lower() if isinstance(mailbox, str) else mailbox,
        "recipient": recipient,
        "delivery_recipient": recipient.lower() if isinstance(recipient, str) else recipient,
        "message_id": message_id.lower() if isinstance(message_id, str) else message_id,
        "content_scope": (
            content_scope.lower() if isinstance(content_scope, str) else content_scope
        ),
        "expires_on": expires_on,
        "approver_role": (
            approver_role.lower() if isinstance(approver_role, str) else approver_role
        ),
        "authority": authority.lower() if isinstance(authority, str) else authority,
        "approval_group": raw.get("approval_group"),
        "renewal_of": raw.get("renewal_of"),
        "subject": raw.get("short_description"),
        "service": "servicenow-approval",
    }
    return _compact(document)


def normalize_exchange_message_trace(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map Exchange Online message trace detail fields to the canonical SaaS shape."""
    accepted = accepted_mail_domains()
    recipients = _recipient_list(raw.get("RecipientAddress"))
    recipient_domains = sorted(
        {domain for recipient in recipients if (domain := _recipient_domain(recipient)) is not None}
    )
    related_recipients = _recipient_list(raw.get("RelatedRecipientAddress"))
    related_domains = sorted(
        {
            domain
            for recipient in related_recipients
            if (domain := _recipient_domain(recipient)) is not None
        }
    )
    external_recipient = (
        any(domain not in accepted for domain in recipient_domains) if recipient_domains else None
    )
    related_external = (
        any(domain not in accepted for domain in related_domains) if related_domains else None
    )
    internal_related = next(
        (
            recipient
            for recipient in related_recipients
            if (domain := _recipient_domain(recipient)) is not None and domain in accepted
        ),
        None,
    )
    internal_recipient = next(
        (
            recipient
            for recipient in recipients
            if (domain := _recipient_domain(recipient)) is not None and domain in accepted
        ),
        None,
    )
    external_targets = [
        recipient
        for recipient in [*recipients, *related_recipients]
        if (domain := _recipient_domain(recipient)) is not None and domain not in accepted
    ]
    delivery_candidates = [*external_targets, *recipients, *related_recipients]
    delivery_recipient = delivery_candidates[0] if delivery_candidates else None
    delivery_recipient = delivery_recipient.lower() if isinstance(delivery_recipient, str) else None
    event = raw.get("Event")
    normalized_event = event.strip().lower() if isinstance(event, str) else ""
    result: str | None = None
    if normalized_event in EXCHANGE_MESSAGE_TRACE_SUCCESS_EVENTS:
        result = "success"
    elif normalized_event == "fail":
        result = "failure"
    elif normalized_event == "defer":
        result = "pending"

    directionality = raw.get("Directionality")
    directionality = (
        directionality.strip().lower() if isinstance(directionality, str) else directionality
    )
    client_ip = raw.get("ClientIP") or raw.get("OriginalClientIP")
    message_id = raw.get("MessageId")

    document: dict[str, Any] = {
        "event_id": raw.get("MessageTraceId"),
        "message_trace_id": raw.get("MessageTraceId"),
        "message_id": message_id.lower() if isinstance(message_id, str) else message_id,
        "sender": raw.get("SenderAddress"),
        "recipient": recipients[0] if recipients else None,
        "recipients": recipients,
        "recipient_domains": recipient_domains,
        "recipient_domain": _recipient_domain(recipients[0]) if recipients else None,
        "external_recipient": external_recipient,
        "subject": raw.get("Subject"),
        "related_recipient": related_recipients[0] if related_recipients else None,
        "related_external": related_external,
        "mailbox": internal_related or internal_recipient,
        "action": raw.get("Event"),
        "trace_event": raw.get("Event"),
        "trace_action": raw.get("Action"),
        "trace_detail": raw.get("Detail"),
        "delivery_status": raw.get("Status"),
        "delivery_recipient": delivery_recipient,
        "delivery_recipients": sorted({recipient.lower() for recipient in external_targets}),
        "directionality": directionality,
        "result": result,
        "size_bytes": raw.get("Size"),
        "from_ip": raw.get("FromIP"),
        "to_ip": raw.get("ToIP"),
        "client_ip": client_ip,
        "tenant_id": raw.get("TenantId"),
        "source_component": raw.get("Source"),
        "trace_reference": raw.get("Reference"),
        "trace_index": raw.get("Index"),
        "service": "exchange",
    }
    return _compact(document)


def normalize_zeek(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map a Zeek log record to the canonical network shape."""
    network = _compact(
        {
            "source_ip": _lookup(raw, "id.orig_h"),
            "source_port": _lookup(raw, "id.orig_p"),
            "destination_ip": _lookup(raw, "id.resp_h"),
            "destination_port": _lookup(raw, "id.resp_p"),
            "protocol": raw.get("proto"),
            "app_protocol": raw.get("service"),
        }
    )
    dns_name = _meaningful(raw.get("query"))
    dns = _compact(
        {
            "query_name": dns_name,
            "query_type": raw.get("qtype_name"),
            "query_length": len(dns_name) if isinstance(dns_name, str) else None,
        }
    )
    http = _compact(
        {
            "host": raw.get("host"),
            "uri": raw.get("uri"),
            "method": raw.get("method"),
            "status": raw.get("status_code"),
            "user_agent": _meaningful(raw.get("user_agent")),
        }
    )
    tls = _compact(
        {
            "sni": raw.get("server_name"),
            "version": raw.get("version"),
            "cipher": raw.get("cipher"),
        }
    )
    document: dict[str, Any] = {
        "flow_id": raw.get("uid"),
        "network_log": raw.get("_path"),
        "bytes_sent": raw.get("orig_bytes"),
        "bytes_received": raw.get("resp_bytes"),
        "user_agent": _meaningful(raw.get("user_agent")),
    }
    if network:
        document["network"] = network
    if dns:
        document["dns"] = dns
    if http:
        document["http"] = http
    if tls:
        document["tls"] = tls
    return _compact(document)


def normalize_suricata(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map a Suricata EVE record to the canonical network shape."""
    network = _compact(
        {
            "source_ip": raw.get("src_ip"),
            "source_port": raw.get("src_port"),
            "destination_ip": raw.get("dest_ip"),
            "destination_port": raw.get("dest_port"),
            "protocol": raw.get("proto"),
            "app_protocol": raw.get("app_proto"),
        }
    )
    alert_raw = raw.get("alert")
    alert: dict[str, Any] = {}
    if isinstance(alert_raw, Mapping):
        alert = _compact(
            {
                "signature": alert_raw.get("signature"),
                "category": alert_raw.get("category"),
                "severity": alert_raw.get("severity"),
            }
        )
    dns_raw = raw.get("dns")
    dns: dict[str, Any] = {}
    if isinstance(dns_raw, Mapping):
        dns_name = _meaningful(dns_raw.get("rrname"))
        dns = _compact(
            {
                "query_name": dns_name,
                "query_type": dns_raw.get("rrtype"),
                "query_length": len(dns_name) if isinstance(dns_name, str) else None,
            }
        )
    http_raw = raw.get("http")
    http: dict[str, Any] = {}
    if isinstance(http_raw, Mapping):
        http = _compact(
            {
                "host": http_raw.get("hostname"),
                "uri": http_raw.get("url"),
                "method": http_raw.get("http_method"),
                "status": http_raw.get("status"),
                "user_agent": _meaningful(http_raw.get("http_user_agent")),
            }
        )
    tls_raw = raw.get("tls")
    tls: dict[str, Any] = {}
    if isinstance(tls_raw, Mapping):
        tls = _compact(
            {
                "sni": tls_raw.get("sni"),
                "version": tls_raw.get("version"),
            }
        )
    flow_raw = raw.get("flow")
    bytes_sent: Any = None
    bytes_received: Any = None
    if isinstance(flow_raw, Mapping):
        bytes_sent = flow_raw.get("bytes_toserver")
        bytes_received = flow_raw.get("bytes_toclient")

    document: dict[str, Any] = {
        "flow_id": raw.get("flow_id"),
        "network_log": raw.get("event_type"),
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "user_agent": http.get("user_agent"),
    }
    if network:
        document["network"] = network
    if alert:
        document["alert"] = alert
    if dns:
        document["dns"] = dns
    if http:
        document["http"] = http
    if tls:
        document["tls"] = tls
    return _compact(document)


def _pod_is_privileged(request_object: Any) -> bool | None:
    if not isinstance(request_object, Mapping) or request_object.get("kind") != "Pod":
        return None
    spec = request_object.get("spec")
    if not isinstance(spec, Mapping):
        return None
    containers: list[Any] = []
    for key in ("containers", "initContainers"):
        value = spec.get(key)
        if isinstance(value, list):
            containers.extend(value)
    if not containers:
        return None
    for container in containers:
        if not isinstance(container, Mapping):
            continue
        security = container.get("securityContext")
        if isinstance(security, Mapping) and security.get("privileged") is True:
            return True
    return False


def normalize_kubernetes_audit(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map a Kubernetes audit record to the canonical Kubernetes shape."""
    user = raw.get("user")
    username: Any = user.get("username") if isinstance(user, Mapping) else None

    object_ref = raw.get("objectRef")
    resource: Any = None
    namespace: Any = None
    name: Any = None
    if isinstance(object_ref, Mapping):
        resource = object_ref.get("resource")
        namespace = object_ref.get("namespace")
        name = object_ref.get("name")

    response = raw.get("responseStatus")
    code: Any = response.get("code") if isinstance(response, Mapping) else None

    source_ips = raw.get("sourceIPs")
    source_ip: Any = source_ips[0] if isinstance(source_ips, list) and source_ips else None

    result: str | None = None
    if isinstance(code, int) and not isinstance(code, bool):
        result = "success" if code < 400 else "failure"

    document: dict[str, Any] = {
        "event_id": raw.get("auditID"),
        "user": username,
        "src_ip": source_ip,
        "action": raw.get("verb"),
        "result": result,
        "resource_name": resource,
        "namespace": namespace,
        "pod": name if resource == "pods" else None,
        "audit_stage": raw.get("stage"),
        "response_status": code,
        "privileged": _pod_is_privileged(raw.get("requestObject")),
    }
    return _compact(document)


def normalize_falco(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map a Falco runtime alert to the canonical Kubernetes shape."""
    fields = raw.get("output_fields")
    output: Mapping[str, Any] = fields if isinstance(fields, Mapping) else {}
    process = _compact(
        {
            "name": output.get("proc.name"),
            "command_line": output.get("proc.cmdline"),
        }
    )
    document: dict[str, Any] = {
        "event_id": raw.get("uuid"),
        "rule_name": raw.get("rule"),
        "priority": raw.get("priority"),
        "host": output.get("hostname"),
        "user": output.get("user.name"),
        "src_ip": output.get("fd.sip"),
        "namespace": output.get("k8s.ns.name"),
        "pod": output.get("k8s.pod.name"),
        "container": output.get("container.name"),
    }
    if process:
        document["process"] = process
    return _compact(document)


NORMALIZERS.update(
    {
        "sysmon": normalize_sysmon,
        "windows-security": normalize_windows_security,
        "aws-cloudtrail": normalize_aws_cloudtrail,
        "m365-audit": normalize_m365_audit,
        "github-audit": normalize_github_audit,
        "exchange-message-trace": normalize_exchange_message_trace,
        "m365-dlp": normalize_m365_dlp,
        "servicenow-approval": normalize_servicenow_approval,
        "zeek": normalize_zeek,
        "suricata": normalize_suricata,
        "kubernetes-audit": normalize_kubernetes_audit,
        "falco": normalize_falco,
    }
)

CLASSIFIERS: dict[str, Classifier] = {
    "sysmon": classify_sysmon,
    "windows-security": classify_windows_security,
    "m365-audit": classify_m365_audit,
    "github-audit": classify_github_audit,
    "exchange-message-trace": classify_exchange_message_trace,
    "zeek": classify_zeek,
    "suricata": classify_suricata,
}


def _required_fields(source: TelemetrySource) -> list[str]:
    values = source.data.get("required_fields")
    if not isinstance(values, list):
        return []
    return [str(value) for value in values]


def dedup_fingerprint(
    source_id: str,
    key_names: Sequence[str],
    raw: Mapping[str, Any],
) -> tuple[str, dict[str, Any], str]:
    """Return a deterministic document ID, key values, and key origin."""
    key_values: dict[str, Any] = {}
    for name in key_names:
        value = _lookup(raw, name)
        if not _present(value):
            break
        key_values[name] = value

    if len(key_values) == len(key_names) and key_values:
        material = {"source": source_id, "key": key_values}
        origin = "declared"
    else:
        key_values = {}
        material = {"source": source_id, "raw": raw}
        origin = "hash"

    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest(), key_values, origin


def normalize_event(
    source: TelemetrySource,
    raw: Mapping[str, Any],
    *,
    ingest_time: datetime,
) -> CanonicalEvent:
    """Validate and normalize one event against its source contract."""
    if not isinstance(raw, Mapping):
        raise IngestError(f"{source.id}: event must be an object")

    normalizer = NORMALIZERS.get(source.id)
    if normalizer is None:
        raise IngestError(f"No normalizer registered for source {source.id!r}")

    missing = [field for field in _required_fields(source) if not _present(_lookup(raw, field))]
    if missing:
        raise IngestError(f"{source.id}: missing required field(s): {', '.join(missing)}")

    event_time_field = str(source.data.get("event_time_field", ""))
    if not event_time_field:
        raise IngestError(f"{source.id}: event_time_field is not declared")
    event_time = parse_timestamp(
        raw.get(event_time_field),
        source=source.id,
        field=event_time_field,
    )

    key_names = source.data.get("dedup_key")
    if not isinstance(key_names, list) or not key_names:
        raise IngestError(f"{source.id}: dedup_key is not declared")
    dedup_id, dedup_key, dedup_origin = dedup_fingerprint(
        source.id,
        [str(name) for name in key_names],
        raw,
    )

    event_classes = source.data.get("event_classes")
    if not isinstance(event_classes, list) or not event_classes:
        raise IngestError(f"{source.id}: event_classes is not declared")
    declared_classes = [str(item) for item in event_classes]
    classifier = CLASSIFIERS.get(source.id)
    event_class = classifier(raw) if classifier is not None else declared_classes[0]
    if event_class not in declared_classes:
        raise IngestError(
            f"{source.id}: classifier returned undeclared event class {event_class!r}"
        )

    document: dict[str, Any] = {
        "@timestamp": format_timestamp(event_time),
        "event_time": format_timestamp(event_time),
        "ingest_time": format_timestamp(ingest_time),
        "source": source.id,
        "event_class": event_class,
        "schema_version": str(source.data.get("schema_version", "")),
        "dedup_key": dedup_key,
        "dedup_origin": dedup_origin,
        "raw": dict(raw),
    }
    document.update(normalizer(raw))

    return CanonicalEvent(
        source=source.id,
        event_class=event_class,
        event_time=event_time,
        ingest_time=ingest_time,
        document=document,
        dedup_id=dedup_id,
    )


def normalize_dataset(
    source: TelemetrySource,
    events: Sequence[Any],
    *,
    ingest_time: datetime,
) -> list[CanonicalEvent]:
    """Normalize every event, reporting the first invalid dataset item."""
    normalized: list[CanonicalEvent] = []
    for position, raw in enumerate(events, start=1):
        try:
            normalized.append(normalize_event(source, raw, ingest_time=ingest_time))
        except IngestError as exc:
            raise IngestError(f"{exc} (dataset item {position})") from exc
    return normalized


def deduplicate_events(
    events: Sequence[CanonicalEvent],
) -> tuple[list[CanonicalEvent], int]:
    """Collapse deterministic IDs, keeping the first occurrence."""
    seen: set[str] = set()
    unique: list[CanonicalEvent] = []
    for event in events:
        if event.dedup_id in seen:
            continue
        seen.add(event.dedup_id)
        unique.append(event)
    return unique, len(events) - len(unique)


def index_name(prefix: str, source_id: str, event_time: datetime) -> str:
    """Return the event-time-based daily index name."""
    utc_time = event_time.astimezone(UTC)
    return f"{prefix}-{source_id}-{utc_time:%Y.%m.%d}"


def load_dataset(source: TelemetrySource, root: Path) -> tuple[Path, list[Any]]:
    """Load, hash-check, and shape-check a source's sample dataset."""
    sample = source.data.get("sample_data")
    if not isinstance(sample, Mapping):
        raise IngestError(f"{source.id}: no sample_data contract")

    path_value = sample.get("path")
    if not isinstance(path_value, str) or not path_value:
        raise IngestError(f"{source.id}: sample_data.path is empty")
    path = root / path_value
    if not path.is_file():
        raise IngestError(f"{source.id}: sample dataset not found: {path}")

    expected_hash = sample.get("sha256")
    if isinstance(expected_hash, str) and sha256_file(path) != expected_hash.lower():
        raise IngestError(f"{source.id}: sample dataset hash does not match: {path}")

    try:
        data = read_json(path)
    except (OSError, ValueError) as exc:
        raise IngestError(f"{source.id}: cannot read sample dataset: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise IngestError(f"{source.id}: sample dataset must be a non-empty JSON array")
    return path, data


class OpenSearchClient:
    """Small OpenSearch client with bulk, count, and cleanup helpers."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._client = httpx.Client(
            base_url=(base_url or config.OPENSEARCH_URL).rstrip("/"),
            timeout=timeout,
            transport=transport,
        )

    def __enter__(self) -> OpenSearchClient:
        return self

    def __exit__(self, *_: object) -> None:
        self._client.close()

    def close(self) -> None:
        self._client.close()

    def bulk(
        self,
        index: str,
        actions: Sequence[tuple[str, Mapping[str, Any]]],
        *,
        refresh: bool,
    ) -> None:
        if not actions:
            return

        lines: list[str] = []
        for doc_id, document in actions:
            lines.append(json.dumps({"index": {"_id": doc_id}}, separators=(",", ":")))
            lines.append(
                json.dumps(
                    dict(document),
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                )
            )
        body = "\n".join(lines) + "\n"

        try:
            response = self._client.post(
                f"/{index}/_bulk",
                content=body.encode("utf-8"),
                headers={"Content-Type": "application/x-ndjson"},
                params={"refresh": "true" if refresh else "false"},
            )
        except httpx.HTTPError as exc:
            raise IngestError(f"Could not reach OpenSearch: {exc}") from exc

        if response.status_code >= 300:
            raise IngestError(
                f"OpenSearch bulk failed with HTTP {response.status_code}: {response.text[:300]}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise IngestError("OpenSearch bulk returned a non-JSON response") from exc
        if not isinstance(payload, Mapping):
            raise IngestError("OpenSearch bulk returned a non-object response")
        if not payload.get("errors"):
            return

        failures: list[dict[str, Any]] = []
        items = payload.get("items")
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                operation = next(iter(item.values()), None)
                if isinstance(operation, Mapping) and operation.get("error"):
                    failures.append(dict(operation))
        detail = json.dumps(failures[0], sort_keys=True)[:500] if failures else "unknown bulk error"
        raise IngestError(f"OpenSearch rejected documents: {detail}")

    def search(self, index: str, body: Mapping[str, Any]) -> dict[str, Any]:
        try:
            response = self._client.post(f"/{index}/_search", json=dict(body))
        except httpx.HTTPError as exc:
            raise IngestError(f"Could not reach OpenSearch: {exc}") from exc

        if response.status_code >= 300:
            raise IngestError(
                f"OpenSearch search failed with HTTP {response.status_code}: {response.text[:300]}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise IngestError("OpenSearch search returned a non-JSON response") from exc
        if not isinstance(payload, Mapping):
            raise IngestError("OpenSearch search returned a non-object response")
        return dict(payload)

    def count(self, index: str) -> int:
        try:
            response = self._client.get(f"/{index}/_count")
        except httpx.HTTPError as exc:
            raise IngestError(f"Could not reach OpenSearch: {exc}") from exc

        if response.status_code == 404:
            return 0
        if response.status_code >= 300:
            raise IngestError(
                f"OpenSearch count failed with HTTP {response.status_code}: {response.text[:300]}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise IngestError("OpenSearch count returned a non-JSON response") from exc
        if not isinstance(payload, Mapping) or not isinstance(payload.get("count"), int):
            raise IngestError("OpenSearch count response did not contain an integer count")
        return int(payload["count"])

    def delete_matching(self, index_pattern: str) -> None:
        try:
            response = self._client.delete(f"/{index_pattern}")
        except httpx.HTTPError as exc:
            raise IngestError(f"Could not reach OpenSearch: {exc}") from exc

        if response.status_code == 404:
            return
        if response.status_code >= 300:
            raise IngestError(
                f"OpenSearch delete failed with HTTP {response.status_code}: {response.text[:300]}"
            )


def write_events(
    client: OpenSearchClient,
    events: Sequence[CanonicalEvent],
    *,
    index_prefix: str,
    refresh: bool,
    batch_size: int,
) -> tuple[int, dict[str, int]]:
    """Write events in batches and return written count and index counts."""
    if batch_size < 1:
        raise IngestError("batch_size must be at least 1")

    grouped: dict[str, list[CanonicalEvent]] = {}
    for event in events:
        target = index_name(index_prefix, event.source, event.event_time)
        grouped.setdefault(target, []).append(event)

    written = 0
    for target in sorted(grouped):
        batch = grouped[target]
        for start in range(0, len(batch), batch_size):
            chunk = batch[start : start + batch_size]
            client.bulk(
                target,
                [(event.dedup_id, event.document) for event in chunk],
                refresh=refresh,
            )
            written += len(chunk)

    counts = {target: client.count(target) for target in sorted(grouped)} if refresh else {}
    return written, counts


def ingest_source(
    source: TelemetrySource,
    root: Path = config.ROOT,
    *,
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> IngestResult:
    """Normalize and ingest one source's sample dataset."""
    dataset, raw_events = load_dataset(source, root)
    event_time = ingest_time or datetime.now(UTC)
    normalized = normalize_dataset(source, raw_events, ingest_time=event_time)
    unique, duplicates = deduplicate_events(normalized)
    indices = tuple(
        sorted({index_name(index_prefix, event.source, event.event_time) for event in unique})
    )

    if dry_run:
        return IngestResult(
            source=source.id,
            dataset=dataset,
            read=len(normalized),
            unique=len(unique),
            duplicates=duplicates,
            indices=indices,
            written=0,
            counts={},
            dry_run=True,
        )

    if client is None:
        with OpenSearchClient() as active:
            written, counts = write_events(
                active,
                unique,
                index_prefix=index_prefix,
                refresh=refresh,
                batch_size=batch_size,
            )
    else:
        written, counts = write_events(
            client,
            unique,
            index_prefix=index_prefix,
            refresh=refresh,
            batch_size=batch_size,
        )

    return IngestResult(
        source=source.id,
        dataset=dataset,
        read=len(normalized),
        unique=len(unique),
        duplicates=duplicates,
        indices=indices,
        written=written,
        counts=counts,
        dry_run=False,
    )


def load_domain_sources(
    domain: str,
    root: Path = config.ROOT,
    requested: Sequence[str] = (),
) -> list[TelemetrySource]:
    """Load and validate the selected source contracts for a domain."""
    supported = DOMAIN_SOURCES.get(domain)
    if supported is None:
        raise IngestError(f"Unknown ingest domain: {domain}")

    sources = {source.id: source for source in load_sources(root)}
    source_ids = list(dict.fromkeys(requested)) or list(supported)

    unknown = [source_id for source_id in source_ids if source_id not in sources]
    if unknown:
        raise IngestError(f"Unknown telemetry source(s): {', '.join(unknown)}")

    unsupported = [source_id for source_id in source_ids if source_id not in supported]
    if unsupported:
        raise IngestError(f"Not {domain} source(s): {', '.join(unsupported)}")

    return [sources[source_id] for source_id in source_ids]


def load_identity_sources(
    root: Path = config.ROOT,
    requested: Sequence[str] = (),
) -> list[TelemetrySource]:
    """Load and validate the selected identity source contracts."""
    return load_domain_sources("identity", root, requested)


def load_endpoint_sources(
    root: Path = config.ROOT,
    requested: Sequence[str] = (),
) -> list[TelemetrySource]:
    """Load and validate the selected endpoint source contracts."""
    return load_domain_sources("endpoint", root, requested)


def load_cloud_sources(
    root: Path = config.ROOT,
    requested: Sequence[str] = (),
) -> list[TelemetrySource]:
    """Load and validate the selected cloud source contracts."""
    return load_domain_sources("cloud", root, requested)


def load_saas_sources(
    root: Path = config.ROOT,
    requested: Sequence[str] = (),
) -> list[TelemetrySource]:
    """Load and validate the selected SaaS source contracts."""
    return load_domain_sources("saas", root, requested)


def load_network_sources(
    root: Path = config.ROOT,
    requested: Sequence[str] = (),
) -> list[TelemetrySource]:
    """Load and validate the selected network source contracts."""
    return load_domain_sources("network", root, requested)


def load_kubernetes_sources(
    root: Path = config.ROOT,
    requested: Sequence[str] = (),
) -> list[TelemetrySource]:
    """Load and validate the selected Kubernetes source contracts."""
    return load_domain_sources("kubernetes", root, requested)


def ingest_domain(
    domain: str,
    root: Path = config.ROOT,
    *,
    sources: Sequence[str] = (),
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> list[IngestResult]:
    """Ingest all selected sources for one telemetry domain."""
    selected = load_domain_sources(domain, root, sources)

    def run(active: OpenSearchClient | None) -> list[IngestResult]:
        return [
            ingest_source(
                source,
                root,
                client=active,
                ingest_time=ingest_time,
                index_prefix=index_prefix,
                refresh=refresh,
                batch_size=batch_size,
                dry_run=dry_run,
            )
            for source in selected
        ]

    if dry_run or client is not None:
        return run(client)
    with OpenSearchClient() as active:
        return run(active)


def ingest_identity(
    root: Path = config.ROOT,
    *,
    sources: Sequence[str] = (),
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> list[IngestResult]:
    """Ingest all selected identity sources into OpenSearch."""
    return ingest_domain(
        "identity",
        root,
        sources=sources,
        client=client,
        ingest_time=ingest_time,
        index_prefix=index_prefix,
        refresh=refresh,
        batch_size=batch_size,
        dry_run=dry_run,
    )


def ingest_endpoint(
    root: Path = config.ROOT,
    *,
    sources: Sequence[str] = (),
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> list[IngestResult]:
    """Ingest all selected endpoint sources into OpenSearch."""
    return ingest_domain(
        "endpoint",
        root,
        sources=sources,
        client=client,
        ingest_time=ingest_time,
        index_prefix=index_prefix,
        refresh=refresh,
        batch_size=batch_size,
        dry_run=dry_run,
    )


def ingest_cloud(
    root: Path = config.ROOT,
    *,
    sources: Sequence[str] = (),
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> list[IngestResult]:
    """Ingest all selected cloud sources into OpenSearch."""
    return ingest_domain(
        "cloud",
        root,
        sources=sources,
        client=client,
        ingest_time=ingest_time,
        index_prefix=index_prefix,
        refresh=refresh,
        batch_size=batch_size,
        dry_run=dry_run,
    )


def ingest_saas(
    root: Path = config.ROOT,
    *,
    sources: Sequence[str] = (),
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> list[IngestResult]:
    """Ingest all selected SaaS sources into OpenSearch."""
    return ingest_domain(
        "saas",
        root,
        sources=sources,
        client=client,
        ingest_time=ingest_time,
        index_prefix=index_prefix,
        refresh=refresh,
        batch_size=batch_size,
        dry_run=dry_run,
    )


def ingest_network(
    root: Path = config.ROOT,
    *,
    sources: Sequence[str] = (),
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> list[IngestResult]:
    """Ingest all selected network sources into OpenSearch."""
    return ingest_domain(
        "network",
        root,
        sources=sources,
        client=client,
        ingest_time=ingest_time,
        index_prefix=index_prefix,
        refresh=refresh,
        batch_size=batch_size,
        dry_run=dry_run,
    )


def ingest_kubernetes(
    root: Path = config.ROOT,
    *,
    sources: Sequence[str] = (),
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> list[IngestResult]:
    """Ingest all selected Kubernetes sources into OpenSearch."""
    return ingest_domain(
        "kubernetes",
        root,
        sources=sources,
        client=client,
        ingest_time=ingest_time,
        index_prefix=index_prefix,
        refresh=refresh,
        batch_size=batch_size,
        dry_run=dry_run,
    )
