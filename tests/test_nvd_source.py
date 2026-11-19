import urllib.error

import pytest

from secure_ai_research.ingestion.nvd_source import NvdApiSource


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
