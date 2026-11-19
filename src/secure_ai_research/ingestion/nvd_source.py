"""NVD API 2.0 CVE source (stdlib only).

``NvdApiSource`` is the project's first outbound network call. The host is a pinned
module constant — ``base_url`` is a constructor parameter for test injection only, never
read from the environment — so ``apiKey`` can never be sent to an attacker-chosen host.
All response validation lives in ``nvd.load``; this module passes bytes through.
"""

import re
import urllib.error
import urllib.parse
import urllib.request

from secure_ai_research.ingestion.source import Opener

# Pinned host (§ design 4/9). cve_id only fills the ``cveId`` query value.
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
_USER_AGENT = "secure-ai-research/0.1 (research tool)"  # generic; no PII


def _default_opener(request: urllib.request.Request, timeout: float) -> bytes:
    with urllib.request.urlopen(request, timeout=timeout) as resp:
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
        headers = {"User-Agent": _USER_AGENT}
        if self._api_key:
            headers["apiKey"] = self._api_key
        request = urllib.request.Request(url, headers=headers)
        try:
            return self._opener(request, self._timeout)
        except urllib.error.HTTPError as exc:
            # api_key is never placed in a message (threat: info disclosure).
            if exc.code in (403, 429):
                raise ValueError("NVD rate limit / forbidden (set SAIR_NVD_API_KEY?)") from exc
            raise ValueError(f"NVD fetch failed for {cve_id}: HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise ValueError(f"NVD fetch failed for {cve_id}: {exc.reason}") from exc
