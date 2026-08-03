"""A thin, bounded wrapper around dnspython.

Checks never touch dnspython directly. Routing every lookup through here means
timeouts, retry limits, answer-size caps and result normalisation are applied
uniformly, and a check author cannot accidentally issue an unbounded query.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver

from .validation import normalize_domain

log = logging.getLogger(__name__)

# A domain answering with thousands of TXT records is either broken or trying
# to blow up the consumer. Truncate and move on.
_MAX_RECORDS_PER_RRSET = 100
_MAX_RECORD_LENGTH = 4096


class DNSError(Exception):
    """A lookup failed for a reason the caller should surface, not swallow."""


class DomainNotFound(DNSError):
    """NXDOMAIN — the name does not exist."""


@dataclass(slots=True)
class DNSAnswer:
    """Normalised result of one lookup."""

    name: str
    rdtype: str
    records: tuple[str, ...] = ()
    exists: bool = True
    truncated: bool = False
    authenticated: bool = False  # AD flag set by a validating resolver

    @property
    def empty(self) -> bool:
        return not self.records


class Resolver:
    """Bounded DNS client.

    Not thread-safe for configuration changes, but individual ``query`` calls
    are safe to make concurrently: dnspython's ``Resolver.resolve`` does not
    mutate shared state once configured.
    """

    def __init__(
        self,
        *,
        timeout: float = 5.0,
        retries: int = 2,
        nameservers: tuple[str, ...] = (),
    ) -> None:
        self.timeout = max(0.5, float(timeout))
        self.retries = max(0, min(int(retries), 5))

        self._resolver = dns.resolver.Resolver(configure=not nameservers)
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.timeout = self.timeout
        # ``lifetime`` bounds the whole operation including retries, so a
        # pathological server cannot hold a worker thread indefinitely.
        self._resolver.lifetime = self.timeout * (self.retries + 1)
        # Never let a search domain silently turn "example" into
        # "example.corp.internal" — every name we query is fully qualified.
        self._resolver.search = []
        self._resolver.use_search_by_default = False

    def query(self, name: str, rdtype: str, *, validate_name: bool = False) -> DNSAnswer:
        """Look up *rdtype* records for *name*.

        Returns a :class:`DNSAnswer` with ``exists=False`` for NXDOMAIN and an
        empty ``records`` tuple for NODATA. Raises :class:`DNSError` only for
        genuine failures (timeout, SERVFAIL, refused) so that callers can tell
        "no record" apart from "could not determine".
        """
        qname = normalize_domain(name) if validate_name else name

        try:
            answer = self._resolver.resolve(
                qname,
                rdtype,
                raise_on_no_answer=False,
                search=False,
            )
        except dns.resolver.NXDOMAIN:
            return DNSAnswer(name=qname, rdtype=rdtype, records=(), exists=False)
        except dns.resolver.NoNameservers as exc:
            # Commonly a DNSSEC validation failure at the upstream resolver.
            raise DNSError(f"no nameserver could answer {rdtype} for {qname}: {exc}") from exc
        except dns.resolver.LifetimeTimeout as exc:
            raise DNSError(f"timed out resolving {rdtype} for {qname}") from exc
        except dns.exception.DNSException as exc:
            raise DNSError(f"DNS error resolving {rdtype} for {qname}: {exc}") from exc

        authenticated = False
        response = getattr(answer, "response", None)
        if response is not None:
            authenticated = bool(response.flags & dns.flags.AD)

        if answer.rrset is None:
            return DNSAnswer(name=qname, rdtype=rdtype, records=(), exists=True, authenticated=authenticated)

        records: list[str] = []
        truncated = False
        for rdata in answer.rrset:
            if len(records) >= _MAX_RECORDS_PER_RRSET:
                truncated = True
                log.warning(
                    "truncating %s answer for %s at %d records", rdtype, qname, _MAX_RECORDS_PER_RRSET
                )
                break
            records.append(_render(rdata)[:_MAX_RECORD_LENGTH])

        # Sort for determinism: many resolvers rotate RRset order, and unsorted
        # output would show up as spurious drift on every single run.
        return DNSAnswer(
            name=qname,
            rdtype=rdtype,
            records=tuple(sorted(records)),
            exists=True,
            truncated=truncated,
            authenticated=authenticated,
        )

    def txt(self, name: str) -> DNSAnswer:
        """TXT lookup with the multi-string concatenation TXT records require.

        A TXT record longer than 255 bytes is transmitted as several character
        strings that must be joined *without* a separator (RFC 7208 §3.3). Long
        SPF and DKIM records rely on this; naive parsers that join with a space
        corrupt them.
        """
        answer = self.query(name, "TXT")
        joined = tuple(sorted(_join_txt(record) for record in answer.records))
        return DNSAnswer(
            name=answer.name,
            rdtype="TXT",
            records=joined,
            exists=answer.exists,
            truncated=answer.truncated,
            authenticated=answer.authenticated,
        )

    def exists(self, name: str) -> bool:
        """True if *name* resolves to anything at all."""
        for rdtype in ("A", "AAAA", "CNAME"):
            try:
                answer = self.query(name, rdtype)
            except DNSError:
                continue
            if not answer.exists:
                return False
            if answer.records:
                return True
        return False


def _render(rdata: object) -> str:
    text = rdata.to_text()  # type: ignore[attr-defined]
    return text.strip()


def _join_txt(record: str) -> str:
    """Reassemble a quoted, possibly multi-part TXT record into its value."""
    text = record.strip()
    if '" "' in text or text.startswith('"'):
        parts = [segment for segment in text.split('"') if segment.strip() != ""]
        return "".join(parts)
    return text
