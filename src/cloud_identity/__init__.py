"""Offline, non-authenticating workload identity policy simulator."""
from .policy import Decision, authorize, lint_policy
__all__ = ["Decision", "authorize", "lint_policy"]
