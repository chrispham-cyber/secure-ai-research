import urllib.error
import urllib.request
from importlib.resources import files

import pytest

from secure_ai_research.ingestion.nvd_source import CachingCveSource, NvdApiSource
from secure_ai_research.ingestion.source import CveNotFound, CveUnavailable


def test_fetch_builds_pinned_url_and_generic_ua():
    seen = {}

    def opener(req, timeout):
        seen["url"] = req.full_url
        seen["ua"] = req.get_header("User-agent")  # urllib Title-cases header keys
        seen["apikey"] = req.get_header("Apikey")
        return b'{"vulnerabilities":[]}'

    NvdApiSource(opener=opener).fetch_raw("CVE-2021-44228")
    assert seen["url"].startswith("https://services.nvd.nist.gov/rest/json/cves/2.0?")
    assert "cveId=CVE-2021-44228" in seen["url"]
    assert seen["ua"] == "secure-ai-research/0.1 (research tool)"
    assert seen["apikey"] is None  # no key configured


def test_api_key_is_sent_when_configured():
    seen = {}

    def opener(req, timeout):
        seen["apikey"] = req.get_header("Apikey")
        return b"{}"

    NvdApiSource(api_key="k-123", opener=opener).fetch_raw("CVE-2021-44228")
    assert seen["apikey"] == "k-123"


def test_malformed_cve_id_rejected_before_network():
    calls = []

    def opener(req, timeout):
        calls.append(req)
        return b"{}"

    for bad in ["../etc/passwd", "CVE-x", "CVE-2021-", "nonsense"]:
        with pytest.raises(ValueError):
            NvdApiSource(opener=opener).fetch_raw(bad)
    assert calls == []  # opener never reached


def test_rate_limit_status_gives_clear_error():
    def opener(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, None)

    with pytest.raises(ValueError, match="rate limit|forbidden"):
        NvdApiSource(opener=opener).fetch_raw("CVE-2021-44228")


def test_api_key_never_appears_in_error():
    def opener(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, None)

    with pytest.raises(ValueError) as exc:
        NvdApiSource(api_key="SECRET-KEY", opener=opener).fetch_raw("CVE-2021-44228")
    assert "SECRET-KEY" not in str(exc.value)


def test_network_error_gives_clear_error():
    def opener(req, timeout):
        raise urllib.error.URLError("dns down")

    with pytest.raises(ValueError, match="CVE-2021-44228"):
        NvdApiSource(opener=opener).fetch_raw("CVE-2021-44228")


def test_api_key_is_unredirected_so_it_cannot_leak_on_a_redirect():
    # Pinned-host invariant (design §4/§6/§9): a configured apiKey must never reach an
    # attacker-chosen host. urllib copies normal headers onto a redirect's new request
    # but NOT unredirected headers, so the key must live in unredirected_hdrs.
    seen = {}

    def opener(req, timeout):
        seen["req"] = req
        return b"{}"

    NvdApiSource(api_key="SECRET-KEY", opener=opener).fetch_raw("CVE-2021-44228")
    req = seen["req"]
    assert req.unredirected_hdrs.get("Apikey") == "SECRET-KEY"
    assert "Apikey" not in req.headers  # not a redirected header → never copied on a 3xx


def test_pinned_host_refuses_to_follow_redirects():
    # A 3xx off the pinned host must fail loud, not be followed (design §4/§9): urllib
    # follows redirects unless redirect_request returns None, which makes it raise instead.
    from secure_ai_research.ingestion.nvd_source import _NoRedirect

    result = _NoRedirect().redirect_request(
        urllib.request.Request("https://services.nvd.nist.gov/rest/json/cves/2.0"),
        None,
        302,
        "Found",
        {},
        "https://evil.example.com/",
    )
    assert result is None


VALID = files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()


class _Spy:
    def __init__(self, raw):
        self.raw = raw
        self.calls = 0

    def fetch_raw(self, cve_id):
        self.calls += 1
        return self.raw


def test_miss_delegates_and_writes(tmp_path):
    spy = _Spy(VALID)
    out = CachingCveSource(spy, tmp_path).fetch_raw("CVE-2099-0001")
    assert out == VALID and spy.calls == 1
    assert (tmp_path / "CVE-2099-0001.json").read_bytes() == VALID


def test_hit_serves_from_disk_without_inner(tmp_path):
    (tmp_path / "CVE-2099-0001.json").write_bytes(VALID)
    spy = _Spy(b"should-not-be-used")
    out = CachingCveSource(spy, tmp_path).fetch_raw("CVE-2099-0001")
    assert out == VALID and spy.calls == 0


def test_empty_vulnerabilities_fails_loud_and_writes_nothing(tmp_path):
    spy = _Spy(b'{"vulnerabilities": []}')
    with pytest.raises(ValueError, match="no usable record"):
        CachingCveSource(spy, tmp_path).fetch_raw("CVE-2099-0001")
    assert not (tmp_path / "CVE-2099-0001.json").exists()


def test_malformed_body_fails_loud_and_writes_nothing(tmp_path):
    spy = _Spy(b"{ this is not json")
    with pytest.raises(ValueError):
        CachingCveSource(spy, tmp_path).fetch_raw("CVE-2099-0001")
    assert not (tmp_path / "CVE-2099-0001.json").exists()


def test_malformed_cve_id_rejected_before_path(tmp_path):
    spy = _Spy(VALID)
    with pytest.raises(ValueError):
        CachingCveSource(spy, tmp_path).fetch_raw("../escape")
    assert spy.calls == 0 and list(tmp_path.iterdir()) == []


def test_http_error_raises_cve_unavailable():
    def opener(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, None)

    with pytest.raises(CveUnavailable):
        NvdApiSource(opener=opener).fetch_raw("CVE-2021-44228")


def test_read_timeout_raises_cve_unavailable():
    # A socket read timeout surfaces as a bare TimeoutError (an OSError), not a URLError;
    # it must still become CveUnavailable, not escape as a 500 / no-audit.
    def opener(req, timeout):
        raise TimeoutError("timed out")

    with pytest.raises(CveUnavailable):
        NvdApiSource(opener=opener).fetch_raw("CVE-2021-44228")


def test_caching_empty_feed_raises_cve_not_found(tmp_path):
    spy = _Spy(b'{"vulnerabilities": []}')
    with pytest.raises(CveNotFound, match="no usable record"):
        CachingCveSource(spy, tmp_path).fetch_raw("CVE-2099-0001")
    assert not (tmp_path / "CVE-2099-0001.json").exists()


def test_caching_malformed_raises_cve_unavailable(tmp_path):
    # Top-level JSON list → nvd.load fails with a non-ValueError (AttributeError); it must
    # still surface as CveUnavailable, and nothing may be cached.
    spy = _Spy(b"[]")
    with pytest.raises(CveUnavailable):
        CachingCveSource(spy, tmp_path).fetch_raw("CVE-2099-0001")
    assert not (tmp_path / "CVE-2099-0001.json").exists()
