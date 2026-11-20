# SBOM in the Release Pipeline + Supply-Chain Checklist — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a reproducible, SHA-256-pinned, test-gated release SBOM built from the pinned runtime lock, flip SR-3 from "planned" to an enforced "met", and sign off the supply-chain checklist.

**Architecture:** A new `supply_chain/` module shells out to the dev-time `cyclonedx-py` CLI (no new runtime import, mirroring how `compliance/evidence.py` shells out to `pytest`), projects the SBOM to a canonical component set, SHA-256-pins it in a committed manifest, and binds the committed SBOM to the lock with hermetic tests the existing `pytest -m "not integration"` CI step runs. SR-3 is wired into the Slice-6 evidence linter so the pin cannot drift.

**Tech Stack:** Python 3.12 stdlib (`subprocess`, `hashlib`, `json`, `re`, `pathlib`), `cyclonedx-bom` (dev dep, CLI only), pytest.

**Spec:** docs/superpowers/specs/2026-11-20-phase5-slice7-sbom-supply-chain-design.md

## Global Constraints
- Deterministic/offline/stdlib default; PUBLIC/synthetic data only.
- NO new **runtime** dependency — `supply_chain` calls `cyclonedx-py` via `subprocess`, imports no new package; base/default install unchanged.
- The release SBOM is generated from the pinned runtime lock `requirements.txt` via `cyclonedx-py requirements requirements.txt --output-reproducible --of json` (verified offline, 24 components, raw-byte-identical across runs, no `timestamp`/`serialNumber`).
- pip-audit stays advisory/non-gating (needs the online advisory DB); do not make it a gate.
- Do NOT modify `src/secure_ai_research/retrieval/authz.py` or `research_service.py`.
- TDD (watch each test fail first); test cmd `./.venv/bin/pytest -q -m "not integration"`; ruff + black clean on changed `.py`.
- Final opus-xhigh whole-branch review; merge-to-main-local; **NO push**.
- Commit footer on every commit:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU`.

## Review Focus
1. **Reproducibility is proven, not assumed** — two generations are byte-identical; a future tool-flag regression must redden a test. → Task 2 `test_release_sbom_is_reproducible`.
2. **`cyclonedx-py requirements` is offline** — the generation tests run in the hermetic suite with no network; if the tool ever needs the network they must move to `-m integration`. → Task 2 (gen runs inside `-m "not integration"`).
3. **PEP 503 name normalization on both sides** — `FastAPI`/`fastapi`, `typing_extensions`/`typing-extensions` must compare equal or completeness false-negatives. → Task 1 `test_normalize_is_pep503` + `test_missing_components_tolerates_name_variants`.
4. **requirements.txt parsing ignores noise** — `# via` comments, blank lines, `-r`/`-c`/`-e` includes, `--hash=` continuations, and `; marker` suffixes are not package names. → Task 1 `test_pinned_requirements_ignores_noise`.
5. **The drift gate actually fails on drift** — a changed/added/removed component without a re-attested manifest must redden the pin. → Task 2 `test_digest_is_sensitive_to_component_change` + `test_manifest_digest_matches_committed_sbom`.

---

### Task 1: `supply_chain` module — pure helpers (parse, normalize, canonicalize, digest, completeness)

**Files:**
- Create: `src/secure_ai_research/supply_chain/__init__.py` (package docstring only)
- Create: `src/secure_ai_research/supply_chain/sbom.py`
- Test: `tests/test_sbom.py`

**Interfaces:**
- Consumes: nothing (stdlib only).
- Produces:
  - `class SbomError(RuntimeError)`
  - `_normalize(name: str) -> str` — PEP 503: lowercase, replace runs of `[-_.]+` with a single `-`.
  - `pinned_requirements(requirements_path: Path) -> set[str]` — normalized distribution names pinned in the lock.
  - `canonical_components(sbom_bytes: bytes) -> list[dict]` — `sorted` list of `{"name","version","purl"}` dicts, ordered by `(name, version)`.
  - `sbom_digest(sbom_bytes: bytes) -> str` — `sha256(json.dumps(canonical_components(sbom_bytes), sort_keys=True, separators=(",", ":")).encode()).hexdigest()`.
  - `missing_components(requirements_path: Path, sbom_bytes: bytes) -> list[str]` — sorted normalized pinned names with no matching normalized SBOM component name.
  - `read_manifest(path: Path) -> dict`.

- [ ] **Step 1: Write failing tests** in `tests/test_sbom.py` (synthetic fixtures — no tool needed):

```python
from pathlib import Path
import json, hashlib
from secure_ai_research.supply_chain.sbom import (
    SbomError, _normalize, pinned_requirements, canonical_components,
    sbom_digest, missing_components, read_manifest,
)

_SBOM = json.dumps({"bomFormat": "CycloneDX", "components": [
    {"type": "library", "name": "FastAPI", "version": "0.163.2", "purl": "pkg:pypi/fastapi@0.163.2"},
    {"type": "library", "name": "anyio", "version": "4.16.0", "purl": "pkg:pypi/anyio@4.16.0"},
]}).encode()

def test_normalize_is_pep503():
    assert _normalize("Typing_Extensions") == _normalize("typing-extensions") == "typing-extensions"
    assert _normalize("a.b_c") == "a-b-c"

def test_pinned_requirements_ignores_noise(tmp_path):
    lock = tmp_path / "r.txt"
    lock.write_text(
        "#\n# autogenerated\n#\nFastAPI==0.163.2\n    # via x\nanyio==4.16.0\n"
        "httpx==0.27.0 ; python_version >= '3.12'\npkg[extra]==1.0\n"
        "-r base.txt\n--hash=sha256:deadbeef\n\n"
    )
    assert pinned_requirements(lock) == {"fastapi", "anyio", "httpx", "pkg"}

def test_canonical_components_is_order_independent():
    rev = json.dumps({"components": list(reversed(json.loads(_SBOM)["components"]))}).encode()
    assert canonical_components(_SBOM) == canonical_components(rev)
    assert sbom_digest(_SBOM) == sbom_digest(rev)

def test_missing_components_tolerates_name_variants(tmp_path):
    lock = tmp_path / "r.txt"
    lock.write_text("fastapi==0.163.2\nany-io==4.16.0\n")   # 'any-io' vs SBOM 'anyio' -> still a miss
    assert missing_components(lock, _SBOM) == ["any-io"]
    lock.write_text("FastAPI==0.163.2\nanyio==4.16.0\n")     # case/variant of present comps -> none
    assert missing_components(lock, _SBOM) == []

def test_read_manifest(tmp_path):
    m = tmp_path / "m.json"; m.write_text('{"sbom_sha256":"abc","component_count":2}')
    assert read_manifest(m)["sbom_sha256"] == "abc"
```

- [ ] **Step 2: Run tests, verify they fail** — `./.venv/bin/pytest tests/test_sbom.py -q` → FAIL (ImportError).
- [ ] **Step 3: Implement the helpers** in `src/secure_ai_research/supply_chain/sbom.py`. `_normalize` via `re.sub(r"[-_.]+", "-", name).lower()`. `pinned_requirements`: for each line, strip; skip empty, lines starting `#`, `-`, or `--`; take the text before `;` (marker); require `==`; take the name before `==`, drop a `[extras]` suffix; add `_normalize(name)`. `canonical_components`: `json.loads`, project each component to `{name,version,purl}`, `sorted` by `(name,version)`. `missing_components`: normalized pinned names minus normalized `{c["name"] for c in components}`.
- [ ] **Step 4: Run tests, verify they pass** — `./.venv/bin/pytest tests/test_sbom.py -q` → PASS.
- [ ] **Step 5: Lint + commit**
```bash
./.venv/bin/ruff check src/secure_ai_research/supply_chain tests/test_sbom.py && ./.venv/bin/black -q src/secure_ai_research/supply_chain tests/test_sbom.py
git add src/secure_ai_research/supply_chain tests/test_sbom.py
git commit -m "feat(supply-chain): SBOM parse/normalize/digest/completeness helpers (Slice 7 Task 1)"
```

---

### Task 2: Reproducible SBOM generation + committed artifacts + the integrity/drift gate

**Files:**
- Modify: `src/secure_ai_research/supply_chain/sbom.py` (add generation + writer)
- Create (committed, generated): `sbom/release-sbom.cdx.json`, `sbom/sbom.manifest.json`
- Test: `tests/test_sbom.py` (add real-generation + gate tests)

**Interfaces:**
- Consumes: Task 1 helpers.
- Produces:
  - `generate_release_sbom(requirements_path: Path, repo_root: Path) -> bytes` — subprocess `cyclonedx-py requirements <requirements_path> --output-reproducible --of json` returning raw SBOM bytes; non-zero exit → `SbomError`. (If `-o -` stdout is unsupported, write to a temp file and read it back — implementer's call, behavior identical.)
  - `write_release_artifacts(repo_root: Path) -> None` — generate from `repo_root/"requirements.txt"`, write `sbom/release-sbom.cdx.json`, and write `sbom/sbom.manifest.json` = `{"source":"requirements.txt","tool":"cyclonedx-py requirements --output-reproducible","sbom_sha256":<digest>,"component_count":<n>,"sbom_file":"sbom/release-sbom.cdx.json"}` (json, 2-space indent, trailing newline).
  - `python -m secure_ai_research.supply_chain.sbom` (a `__main__` block) calls `write_release_artifacts(Path.cwd())` — the re-attest entry point `make sbom-release` invokes.

- [ ] **Step 1: Write failing tests** in `tests/test_sbom.py` (real generation + the committed-artifact gate; they are RED because the function is undefined AND the artifacts do not exist yet):
```python
import secure_ai_research.supply_chain.sbom as S

_REPO = Path(__file__).resolve().parents[1]
_REQ = _REPO / "requirements.txt"
_SBOM_FILE = _REPO / "sbom/release-sbom.cdx.json"
_MANIFEST = _REPO / "sbom/sbom.manifest.json"

def test_generate_release_sbom_raises_on_bad_path(tmp_path):
    import pytest
    with pytest.raises(SbomError):
        S.generate_release_sbom(tmp_path / "nope.txt", _REPO)

def test_release_sbom_is_reproducible():
    a = S.generate_release_sbom(_REQ, _REPO); b = S.generate_release_sbom(_REQ, _REPO)
    assert a == b  # Review Focus 1

def test_sbom_is_well_formed_cyclonedx():
    d = json.loads(_SBOM_FILE.read_bytes())
    assert d["bomFormat"] == "CycloneDX"
    assert d["components"] and all(c.get("name") and c.get("version") and c.get("purl") for c in d["components"])

def test_committed_sbom_matches_regeneration():
    fresh = S.generate_release_sbom(_REQ, _REPO)
    assert S.sbom_digest(fresh) == S.sbom_digest(_SBOM_FILE.read_bytes())  # drift gate

def test_manifest_digest_matches_committed_sbom():
    man = S.read_manifest(_MANIFEST)
    sbom = _SBOM_FILE.read_bytes()
    assert man["sbom_sha256"] == S.sbom_digest(sbom)
    assert man["component_count"] == len(json.loads(sbom)["components"])

def test_sbom_covers_every_pinned_runtime_dependency():
    assert S.missing_components(_REQ, _SBOM_FILE.read_bytes()) == []  # SR-3 evidence node

def test_digest_is_sensitive_to_component_change():
    d = json.loads(_SBOM_FILE.read_bytes()); d["components"][0]["version"] = "9.9.9-mutant"
    assert S.sbom_digest(json.dumps(d).encode()) != S.read_manifest(_MANIFEST)["sbom_sha256"]  # Review Focus 5
```

- [ ] **Step 2: Run tests, verify they fail** — `./.venv/bin/pytest tests/test_sbom.py -q` → FAIL (`generate_release_sbom` undefined; artifacts absent).
- [ ] **Step 3: Implement** `generate_release_sbom`, `write_release_artifacts`, and the `if __name__ == "__main__":` block in `sbom.py`.
- [ ] **Step 4: Produce + stage the committed artifacts**
```bash
cd <repo-root> && ./.venv/bin/python -m secure_ai_research.supply_chain.sbom && git add sbom/release-sbom.cdx.json sbom/sbom.manifest.json
```
- [ ] **Step 5: Run tests, verify they pass** — `./.venv/bin/pytest tests/test_sbom.py -q` → PASS.
- [ ] **Step 6: Lint + commit**
```bash
./.venv/bin/ruff check src/secure_ai_research/supply_chain tests/test_sbom.py && ./.venv/bin/black -q src/secure_ai_research/supply_chain tests/test_sbom.py
git add src/secure_ai_research/supply_chain tests/test_sbom.py sbom/
git commit -m "feat(supply-chain): reproducible release SBOM + SHA-256 pin + drift gate (Slice 7 Task 2)"
```

---

### Task 3: Wire SR-3 into the evidence matrix + sign-off docs + Makefile + CI

**Files:**
- Modify: `documentation/assessment-evidence/control-evidence-matrix.md` (SR-3 row)
- Modify: `security-controls/supply-chain/sbom.md` (sign-off), `documentation/sbom/sbom-guide.md`, `scripts/gen-sbom.sh`
- Modify: `Makefile` (add `sbom-release`), `.github/workflows/ci.yml` (repoint SBOM step)
- Test: relies on Slice-6 `tests/test_control_evidence.py` + `tests/test_compliance_docs.py` (no new test file)

**Interfaces:**
- Consumes: Task 1/2 (`supply_chain/sbom.py`, `tests/test_sbom.py` nodes).
- Produces: an enforced SR-3 citation.

- [ ] **Step 1: Flip SR-3** in `control-evidence-matrix.md`: status `planned` → **met**; Evidence `src/secure_ai_research/supply_chain/sbom.py`; Verified by `tests/test_sbom.py::test_sbom_covers_every_pinned_runtime_dependency`, `tests/test_sbom.py::test_committed_sbom_matches_regeneration`; keep the `documentation/sbom/sbom-guide.md` reference in the claim prose. (Claim: "Reproducible release SBOM from the pinned lock, SHA-256-pinned in a committed manifest; a dependency change that is not re-attested fails CI.")
- [ ] **Step 2: Run the Slice-6 gates, verify green** (they now enforce the new SR-3 citation):
  Run: `./.venv/bin/pytest tests/test_control_evidence.py tests/test_compliance_docs.py -q` → PASS (paths exist, nodes collect, not skip-marked, no template markers).
- [ ] **Step 3: Sign off the checklist** in `security-controls/supply-chain/sbom.md`: replace the per-release `- [ ]` list with a dated **v0.1.0 sign-off** (lock reviewed; pip-audit reviewed; reproducible SBOM produced + SHA-256-pinned in `sbom/sbom.manifest.json`; gitleaks clean; model hashes verified; base images pinned), describe the reproducible release SBOM + manifest/digest drift gate, and name cryptographic signing (cosign/sigstore) as future work. Update `documentation/sbom/sbom-guide.md` (generation command → `make sbom-release`; describe the manifest/digest gate). In `scripts/gen-sbom.sh`, add a comment pointing to `make sbom-release` for the pinned artifact (leave the `environment` dev command).
- [ ] **Step 4: Makefile `sbom-release` + CI**: add
```make
sbom-release: ## Generate the reproducible release SBOM + rewrite the integrity manifest
	./.venv/bin/python -m secure_ai_research.supply_chain.sbom
```
  to `Makefile` (add target to `.PHONY`). In `.github/workflows/ci.yml`, repoint the `SBOM (CycloneDX)` step to `python -m secure_ai_research.supply_chain.sbom` (or `make sbom-release`) and upload `sbom/release-sbom.cdx.json`; leave pip-audit `continue-on-error`.
- [ ] **Step 5: Verify docs gate + full suite**
  Run: `./.venv/bin/pytest -q -m "not integration"` → PASS (all green incl. Slice-6 gates + new SBOM tests).
- [ ] **Step 6: Commit**
```bash
git add documentation/ security-controls/ scripts/gen-sbom.sh Makefile .github/workflows/ci.yml
git commit -m "feat(supply-chain): enforce SR-3 in evidence matrix + sign off checklist + CI (Slice 7 Task 3)"
```

---

## Notes for the executor
- `tests/test_sbom.py` is hermetic: `cyclonedx-py` is a dev dependency, always present wherever the suite runs; generation is offline and reads only `requirements.txt`. Do **not** mark it `integration`.
- If `generate_release_sbom` is found to need the network (it must not, per recon), stop and reconsider — that would move the generation tests to `-m integration` and change the gate's reach.
- The committed `sbom/` artifacts are intentional (the pin); only the ad-hoc `sbom.json` (environment dev output) stays git-ignored.
