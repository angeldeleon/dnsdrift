"""dnsdrift — agentless drift detection for DNS, email authentication and TLS.

Read-only by construction: the tool issues DNS queries, completes one TLS
handshake per host to read its certificate, and queries Certificate
Transparency logs. It never sends application data to a scanned host, never
attempts authentication, and never modifies anything.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
