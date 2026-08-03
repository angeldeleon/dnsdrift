"""Check implementations.

Importing this package registers every built-in check. New checks should
``@register("name")`` in a module imported here and add their name to
``dnsdrift.config.ALL_CHECKS``.
"""

from __future__ import annotations

# Imported for their registration side effects.
from . import ct, dns_hygiene, email_auth, tls  # noqa: F401  (side-effect imports)
from .base import CheckContext, get_check, register, registered_checks

__all__ = ["CheckContext", "get_check", "register", "registered_checks"]
