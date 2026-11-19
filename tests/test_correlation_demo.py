from secure_ai_research.audit.record import read_records
from secure_ai_research.demo.correlation import (
    _PIVOTS,
    _source_of,
    build_correlation_report,
    build_offline_corpus,
    correlate,
)

_KEV = "CISA KEV (known-exploited)"
_SIGMA = "SigmaHQ (detection)"
_ATTACK = "MITRE ATT&CK (technique)"


def _corpus(tmp_path):
    audit = tmp_path / "audit.jsonl"
    return build_offline_corpus(audit), audit


def test_source_of_maps_each_namespace():
    assert _source_of("KEV-CVE-2021-44228") == _KEV
    assert _source_of("SIGMA-abc") == _SIGMA
    assert _source_of("T1059") == _ATTACK
    assert _source_of("T1059.001") == _ATTACK
    assert _source_of("CVE-2099-0001") == "NVD (vulnerability)"
    assert _source_of("weird-id") == "other"


def test_correlate_cve_is_exactly_kev_and_sigma(tmp_path):
    svc, _ = _corpus(tmp_path)
    result = correlate(svc, "CVE-2021-44228")
    assert result == {
        _KEV: ["KEV-CVE-2021-44228"],
        _SIGMA: ["SIGMA-3eb91f0a-0060-424a-a676-59f5fdd75610"],
    }


def test_correlate_technique_spans_attack_and_sigma(tmp_path):
    svc, _ = _corpus(tmp_path)
    result = correlate(svc, "T1059")
    assert _ATTACK in result and "T1059" in result[_ATTACK]
    assert _SIGMA in result and any(i.startswith("SIGMA-") for i in result[_SIGMA])


def test_report_renders_both_pivots(tmp_path):
    svc, _ = _corpus(tmp_path)
    report = build_correlation_report(svc, _PIVOTS)
    assert "CVE-2021-44228" in report and "KEV-CVE-2021-44228" in report
    assert "T1059" in report and "SIGMA-" in report
    assert _KEV in report and _ATTACK in report and _SIGMA in report


def test_one_audit_record_per_pivot_with_correlated_sources(tmp_path):
    svc, audit = _corpus(tmp_path)
    build_correlation_report(svc, _PIVOTS)  # two searches
    records = read_records(audit)
    assert len(records) == 2
    cve_rec = next(r for r in records if "KEV-CVE-2021-44228" in r.retrieved_doc_ids)
    assert {"CISA KEV", "Sigma"} <= set(cve_rec.data_source_ids)
    # the audit records the FULL ranked retrieved set, not the clean correlate() pair
    assert cve_rec.data_source_ids == ["CISA KEV", "MITRE ATT&CK", "NVD", "Sigma"]
