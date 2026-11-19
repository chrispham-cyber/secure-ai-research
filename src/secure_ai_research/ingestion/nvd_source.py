"""NVD API 2.0 CVE source (stdlib only).

``NvdApiSource`` is the project's first outbound network call. The host is a pinned
module constant — ``base_url`` is a constructor parameter for test injection only, never
read from the environment. Two measures keep ``apiKey`` from reaching an attacker-chosen
host: redirects are refused (a 3xx off the pinned host fails loud instead of being
followed), and the key is sent as an *unredirected* header (urllib never copies it onto
a redirect's new request). All response validation lives in ``nvd.load``; this module
passes bytes through.
"""

import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from secure_ai_research.ingestion import nvd
from secure_ai_research.ingestion.source import (
    CveNotFound,
    CveSource,
    CveUnavailable,
    Opener,
)

# Pinned host (§ design 4/9). cve_id only fills the ``cveId`` query value.
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
_USER_AGENT = "secure-ai-research/0.1 (research tool)"  # generic; no PII


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Pinned host: refuse every 3xx so a redirect fails loud and is never followed."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


# Opener without redirect-following; the host is pinned, so a 3xx is an error, not a hop.
_OPENER = urllib.request.build_opener(_NoRedirect())


def _default_opener(request: urllib.request.Request, timeout: float) -> bytes:
    with _OPENER.open(request, timeout=timeout) as resp:
        data: bytes = resp.read()
    return data


class NvdApiSource:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = NVD_CVE_API,
        timeout: float = 30.0,
        opener: Opener | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url
        self._timeout = timeout
        self._opener = opener or _default_opener

    def fetch_raw(self, cve_id: str) -> bytes:
        if not _CVE_ID.match(cve_id):
            raise ValueError(f"invalid CVE id: {cve_id!r}")
        url = f"{self._base_url}?" + urllib.parse.urlencode({"cveId": cve_id})
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        if self._api_key:
            # Unredirected: urllib never copies this onto a redirect's new request, so the
            # key cannot reach another host even if a redirect were somehow followed.
            request.add_unredirected_header("apiKey", self._api_key)
        try:
            return self._opener(request, self._timeout)
        except urllib.error.HTTPError as exc:
            # api_key is never placed in a message (threat: info disclosure).
            if exc.code in (403, 429):
                raise CveUnavailable("NVD rate limit / forbidden (set SAIR_NVD_API_KEY?)") from exc
            raise CveUnavailable(f"NVD fetch failed for {cve_id}: HTTP {exc.code}") from exc
        except OSError as exc:
            # OSError covers URLError (itself an OSError) and a bare TimeoutError raised
            # from resp.read() after the connection opened. api_key never appears here.
            raise CveUnavailable(f"NVD fetch failed for {cve_id}: {exc}") from exc


class CachingCveSource:
    """Read/write-through on-disk cache in front of any CveSource.

    A cache miss persists the response only if ``nvd.load`` accepts it (the same single
    gate reused as a go/no-go), so a 200-with-``[]`` or a garbled body never poisons the
    cache into permanent NOT_FOUND. A hit is served without re-validation — it passed the
    gate when written. The port still returns bytes; this class never parses on its own.
    """

    def __init__(self, inner: CveSource, cache_dir: Path) -> None:
        self._inner = inner
        self._cache_dir = cache_dir

    def fetch_raw(self, cve_id: str) -> bytes:
        if not _CVE_ID.match(cve_id):
            raise ValueError(f"invalid CVE id: {cve_id!r}")
        path = self._cache_dir / f"{cve_id}.json"
        if path.exists():
            return path.read_bytes()
        raw = self._inner.fetch_raw(cve_id)
        try:
            docs = nvd.load(raw)
        except Exception as exc:  # any parse failure (incl. non-ValueError) → unavailable
            raise CveUnavailable(f"NVD returned an unparseable record for {cve_id}: {exc}") from exc
        if not docs:  # parsed cleanly but empty "vulnerabilities" → absent, not an error
            raise CveNotFound(f"NVD returned no usable record for {cve_id}")
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_bytes(raw)
        os.replace(tmp, path)
        return raw
