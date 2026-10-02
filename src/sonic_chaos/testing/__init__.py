"""Test doubles for code that drives a switch. Import-safe: no pytest, no sonic-mgmt."""
from .recording import RecordingDut, normalize

__all__ = ["RecordingDut", "normalize"]
