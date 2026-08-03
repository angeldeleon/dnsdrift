"""A thin, bounded wrapper around dnspython.

Checks never touch dnspython directly. Routing every lookup through here means
timeouts, retry limits, answer-size caps and result normalisation are applied
uniformly, and a check author cannot accidentally issue an unbounded query.

The single most important property here is that **a lookup failure is never
silently converted into "no record"**. Every method distinguishes three states —
the record exists, it definitively does not, or we could not find out — because
collapsing the third into the second is what makes a monitoring tool produce
confident false alarms.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver

from .validation import normalize_domain

log = logging.getLogger(__name__)

# A domain answering with thousands of TXT records is either broken or trying
# to blow up the consumer. Cap it, and tell the caller we did.
_MAX_RECORDS_PER_RRSET = 100
_MAX_RECORD_LENGTH = 4096


class DNSError(Exception):
    """A lookup failed for a reason the caller should surface, not swallow."""


class DomainNotFound(DNSError):
    """NXDOMAIN — the name does not exist."""


class NameStatus(str, Enum):
    """Whether a name resolves.

    ``NXDOMAIN`` and ``NODATA`` are deliberately distinct. For subdomain-takeover
    detection only NXDOMAIN matters: the target name is unregistered and can be
    claimed. A NODATA name exists (it may hold only MX or TXT records) and is not
    claimable, so reporting it as dangling would be a false positive.
    """

    RESOLVES = "resolves"
    NXDOMAIN = "nxdomain"
    NODATA = "nodata"


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

        records = [_render(rdata)[:_MAX_RECORD_LENGTH] for rdata in answer.rrset]

        # Sort BEFORE truncating. Many resolvers rotate RRset order between
        # responses, so slicing the wire order first would select a different
        # subset each run and manufacture drift on every single scan.
        records.sort()
        truncated = len(records) > _MAX_RECORDS_PER_RRSET
        if truncated:
            log.warning(
                "truncating %s answer for %s: %d records exceeds the %d cap",
                rdtype,
                qname,
                len(records),
                _MAX_RECORDS_PER_RRSET,
            )
            records = records[:_MAX_RECORDS_PER_RRSET]

        return DNSAnswer(
            name=qname,
            rdtype=rdtype,
            records=tuple(records),
            exists=True,
            truncated=truncated,
            authenticated=authenticated,
        )

    def txt(self, name: str) -> DNSAnswer:
        """TXT lookup with the multi-string concatenation TXT records require.

        A TXT record longer than 255 bytes is transmitted as several character
        strings that must be joined *without* a separator (RFC 7208 §3.3). Long
        SPF and DKIM records rely on this.

        The join is done from dnspython's decoded ``strings`` rather than by
        re-parsing ``to_text()``. Re-parsing quoted output loses whitespace-only
        segments and mangles records containing escaped quotes, either of which
        silently corrupts the record and shows up later as phantom drift.
        """
        qname = name

        try:
            answer = self._resolver.resolve(qname, "TXT", raise_on_no_answer=False, search=False)
        except dns.resolver.NXDOMAIN:
            return DNSAnswer(name=qname, rdtype="TXT", records=(), exists=False)
        except dns.resolver.NoNameservers as exc:
            raise DNSError(f"no nameserver could answer TXT for {qname}: {exc}") from exc
        except dns.resolver.LifetimeTimeout as exc:
            raise DNSError(f"timed out resolving TXT for {qname}") from exc
        except dns.exception.DNSException as exc:
            raise DNSError(f"DNS error resolving TXT for {qname}: {exc}") from exc

        authenticated = False
        response = getattr(answer, "response", None)
        if response is not None:
            authenticated = bool(response.flags & dns.flags.AD)

        if answer.rrset is None:
            return DNSAnswer(name=qname, rdtype="TXT", records=(), exists=True, authenticated=authenticated)

        records: list[str] = []
        for rdata in answer.rrset:
            strings = getattr(rdata, "strings", None)
            if strings is None:  # pragma: no cover - defensive
                records.append(_render(rdata)[:_MAX_RECORD_LENGTH])
                continue
            joined = b"".join(strings)
            records.append(joined.decode("utf-8", errors="replace")[:_MAX_RECORD_LENGTH])

        records.sort()
        truncated = len(records) > _MAX_RECORDS_PER_RRSET
        if truncated:
            log.warning("truncating TXT answer for %s at %d records", qname, _MAX_RECORDS_PER_RRSET)
            records = records[:_MAX_RECORDS_PER_RRSET]

        return DNSAnswer(
            name=qname,
            rdtype="TXT",
            records=tuple(records),
            exists=True,
            truncated=truncated,
            authenticated=authenticated,
        )

    def name_status(self, name: str) -> NameStatus:
        """Determine whether *name* resolves, distinguishing NXDOMAIN from NODATA.

        Raises :class:`DNSError` if every probe failed — the caller must not be
        able to mistake "we could not reach a nameserver" for "the name does not
        exist". That mistake is what turns a transient SERVFAIL on a CDN into a
        confident CRITICAL "subdomain takeover" alert.
        """
        failures: list[str] = []
        saw_nodata = False

        for rdtype in ("A", "AAAA", "CNAME"):
            try:
                answer = self.query(name, rdtype)
            except DNSError as exc:
                failures.append(str(exc))
                continue
            if not answer.exists:
                return NameStatus.NXDOMAIN
            if answer.records:
                return NameStatus.RESOLVES
            saw_nodata = True

        if saw_nodata:
            return NameStatus.NODATA

        raise DNSError(
            f"could not determine whether {name} resolves; all lookups failed ({'; '.join(failures[:3])})"
        )


def _render(rdata: object) -> str:
    text = rdata.to_text()  # type: ignore[attr-defined]
    return text.strip()
