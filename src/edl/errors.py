"""Package-specific exceptions."""

from __future__ import annotations


class EDLError(Exception):
    """Base class for expected CLI errors."""


class LabError(EDLError):
    """Raised when the local lab cannot be reached or bootstrapped."""


class ValidationError(EDLError):
    """Raised when repository artifacts fail validation."""


class IngestError(EDLError):
    """Raised when telemetry cannot be normalized or ingested."""
