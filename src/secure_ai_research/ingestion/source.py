"""Port for a source of raw CVE feed bytes.

An implementation returns the raw NVD 2.0 feed JSON (``{"vulnerabilities":[{"cve":...}]}``)
for a CVE id; ``nvd.load`` is the single gate that parses and validates those bytes.
"""

import urllib.request
from collections.abc import Callable
from typing import Protocol

# A thin HTTP transport seam: given a prepared request and a timeout, return the
# response body as bytes. Injected into NvdApiSource so unit tests stay hermetic.
Opener = Callable[[urllib.request.Request, float], bytes]


class CveSource(Protocol):
    def fetch_raw(self, cve_id: str) -> bytes: ...
