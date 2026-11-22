"""Reference artifact scaffolding."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from . import config
from .artifacts import DOMAIN_BY_CODE, expected_domain_from_id
from .errors import ValidationError

DETECTION_ID_RE = re.compile(r"^DET-(IDN|END|CLD|SAA|NET|K8S|AGT)-[0-9]{3}$")
INVESTIGATION_ID_RE = re.compile(r"^INV-[0-9]{3}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
TEXT_SUFFIXES = {".json", ".md", ".py", ".yaml", ".yml"}

TEMPLATE_DETECTION = config.ROOT / "detections" / "endpoint" / "_template"
TEMPLATE_INVESTIGATION = config.ROOT / "investigations" / "_template"
REFERENCE_DETECTION_TITLE = "Reference Detection — Whoami Execution"
REFERENCE_INVESTIGATION_TITLE = "Reference Investigation — Synthetic Identity to Cloud"


def _validate_slug(slug: str) -> None:
    if not SLUG_RE.fullmatch(slug):
        raise ValidationError(
            "slug must be lowercase, hyphen-separated, and start with a letter or number"
        )


def _validate_title(title: str) -> None:
    if len(title.strip()) < 8:
        raise ValidationError("title must be at least 8 characters")


def _replace_in_tree(target: Path, replacements: dict[str, str]) -> None:
    for path in target.rglob("*"):
        if not path.is_file() or path.suffix not in TEXT_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8")
        updated = text
        for old, new in replacements.items():
            updated = updated.replace(old, new)
        if updated != text:
            path.write_text(updated, encoding="utf-8")


def new_detection(
    domain: str,
    slug: str,
    detection_id: str,
    title: str,
    *,
    root: Path = config.ROOT,
    dry_run: bool = False,
) -> Path:
    """Create a detection package from the working reference template."""
    if domain not in set(DOMAIN_BY_CODE.values()):
        allowed = ", ".join(sorted(set(DOMAIN_BY_CODE.values())))
        raise ValidationError(f"domain must be one of: {allowed}")
    _validate_slug(slug)
    _validate_title(title)
    if not DETECTION_ID_RE.fullmatch(detection_id):
        raise ValidationError(f"invalid detection ID: {detection_id}")
    expected_domain = expected_domain_from_id(detection_id)
    if expected_domain != domain:
        raise ValidationError(
            f"detection ID {detection_id} implies domain {expected_domain}, not {domain}"
        )

    target = root / "detections" / domain / slug
    if target.exists():
        raise ValidationError(f"target already exists: {target}")
    if dry_run:
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(TEMPLATE_DETECTION, target)
    _replace_in_tree(
        target,
        {
            "DET-END-000": detection_id,
            REFERENCE_DETECTION_TITLE: title,
            "domain: endpoint": f"domain: {domain}",
        },
    )

    from .validation import validate_repository

    report = validate_repository(root, include_path=target)
    if not report.ok:
        messages = "; ".join(issue.message for issue in report.errors)
        shutil.rmtree(target)
        raise ValidationError(f"scaffolded detection did not validate: {messages}")

    return target


def new_investigation(
    slug: str,
    investigation_id: str,
    title: str,
    *,
    root: Path = config.ROOT,
    dry_run: bool = False,
) -> Path:
    """Create an investigation package from the working reference template."""
    _validate_slug(slug)
    _validate_title(title)
    if not INVESTIGATION_ID_RE.fullmatch(investigation_id):
        raise ValidationError(f"invalid investigation ID: {investigation_id}")

    target = root / "investigations" / slug
    if target.exists():
        raise ValidationError(f"target already exists: {target}")
    if dry_run:
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(TEMPLATE_INVESTIGATION, target)
    _replace_in_tree(
        target,
        {
            "INV-000": investigation_id,
            REFERENCE_INVESTIGATION_TITLE: title,
        },
    )

    from .validation import validate_repository

    report = validate_repository(root, include_path=target)
    if not report.ok:
        messages = "; ".join(issue.message for issue in report.errors)
        shutil.rmtree(target)
        raise ValidationError(f"scaffolded investigation did not validate: {messages}")

    return target
