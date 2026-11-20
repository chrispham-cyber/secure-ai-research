# SBOM Signing (keyed, offline cosign) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a keyed, offline cosign signature over the release SBOM file bytes, verified in CI with the public key only, without disturbing the offline/stdlib default suite.

**Architecture:** A new stdlib `supply_chain/signing.py` shells out to the `cosign` binary (mirroring `supply_chain/sbom.py`→`cyclonedx-py`). Hermetic tests cover the pure command builders + artifact gates; a skip-clean `-m integration` test covers the real round-trip. CI gains a `sbom-verify` job (public key only, no `id-token`) that skips until a signature is committed and gates once it is. Docs + the SR-3 evidence row are updated.

**Tech Stack:** Python 3.12 stdlib (`subprocess`, `shutil`, `pathlib`, `sys`); `cosign` (external Go binary, not a pip dep); GitHub Actions; pytest.

**Spec:** `docs/superpowers/specs/2026-11-20-sbom-signing-design.md`

## Global Constraints
- Repo stays **PRIVATE**; push to the private origin is authorized for this slice. Attribution footer on every commit (`Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` + `Claude-Session:` line).
- The default `-m "not integration"` suite MUST stay offline/stdlib: it must never require `cosign` installed or any network. `import secure_ai_research.supply_chain.signing` imports nothing heavy (no `sigstore`, no `cryptography`).
- **No new pip dependency** — `cosign` is a binary, shelled out. No `[sign]` extra.
- `.gitignore` keeps blocking `*.key`/`*.pem`; never commit or echo a private key.
- CI `sbom-verify` uses the committed **public key only** — no secret, no `id-token`, job `permissions: contents: read`.
- Sign the **whole SBOM file bytes** (`sbom/release-sbom.cdx.json`), not the manifest or the projection.
- Do NOT fabricate a signature: ship with the CI verify job **skipping until a real `sbom/cosign.pub` + `.sig` are committed** (the one-time key ceremony is Chris's, documented).
- Keep green: `tests/test_sbom.py`, `tests/test_compose_pinning.py`, `tests/test_dev_lock.py`, `tests/test_stubs.py`, `tests/test_compliance_docs.py`, `tests/test_control_evidence.py`. Do not touch `retrieval/authz.py` or `research_service.py`.
- Test command: `./.venv/bin/pytest -q -m "not integration"`.

## Review Focus
- **cosign-absent posture:** with no `cosign` on PATH and no network, the hermetic suite stays fully green and the integration test skips cleanly (not errors). Pinned by `test_signing.py` not importing anything heavy + the integration test's `_require_cosign` skip.
- **Half-done ceremony:** `sbom/cosign.pub` present but `.sig` absent (or vice-versa) must redden the all-or-nothing artifact gate, and the CI job must not falsely pass. Pinned by `test_committed_signing_artifacts_are_all_or_nothing`.
- **Stale signature:** SBOM re-attested via `make sbom-release` but not re-signed ⇒ the CI `sbom-verify` job must fail. The hermetic suite cannot verify crypto, so confirm the design routes this to the CI job (not left ungated) — the integration test asserts the committed-signature verify when present.
- **CI verify security:** the `sbom-verify` job has no `id-token`, no secret, reads the committed `sbom/cosign.pub` (not an attacker-supplied key). Pinned by `test_signing_wiring.py::test_sbom_verify_job_is_public_key_only`.
- **Private-key leak:** `.gitignore` blocks `*.key`; `sign_release_sbom`/`__main__` never echo the key ref's contents. Pinned by a `.gitignore` assertion in `test_signing_wiring.py`.

---

### Task 1: Signing module + hermetic tests + integration round-trip

**Files:**
- Create: `src/secure_ai_research/supply_chain/signing.py`
- Create: `tests/test_signing.py` (hermetic)
- Create: `tests/test_integration_signing.py` (`-m integration`, skip-clean)

**Interfaces — Produces:**
- `SigningError(RuntimeError)`
- `sign_command(key_ref: str, sbom: str, sig: str) -> list[str]`
- `verify_command(pub: str, sig: str, sbom: str) -> list[str]`
- `cosign_available() -> bool`
- `signing_artifacts_state(repo_root: Path) -> tuple[bool, bool]`  # (sig_present, pub_present), non-empty
- `sign_release_sbom(repo_root: Path, key_ref: str) -> None`
- `verify_release_sbom(repo_root: Path) -> bool`
- Module constants `_SBOM`, `_SIG`, `_PUB`.

**Consumes:** nothing new (`pathlib`, `subprocess`, `shutil`, `sys`).

- [ ] **Step 1: Write the failing hermetic test** `tests/test_signing.py`:

```python
def test_sign_command_is_offline():
    cmd = sign_command("cosign.key", "sbom/x.json", "sbom/x.json.sig")
    assert cmd == ["cosign","sign-blob","--key","cosign.key",
                   "--tlog-upload=false","--yes",
                   "--output-signature","sbom/x.json.sig","sbom/x.json"]

def test_verify_command_ignores_transparency_log():
    cmd = verify_command("sbom/cosign.pub","sbom/x.json.sig","sbom/x.json")
    assert cmd == ["cosign","verify-blob","--key","sbom/cosign.pub",
                   "--insecure-ignore-tlog=true",
                   "--signature","sbom/x.json.sig","sbom/x.json"]

def test_cosign_available_reflects_path(monkeypatch):
    monkeypatch.setattr(signing.shutil, "which", lambda _:"/usr/bin/cosign")
    assert cosign_available() is True
    monkeypatch.setattr(signing.shutil, "which", lambda _:None)
    assert cosign_available() is False

def test_signing_artifacts_state_tmp(tmp_path):
    assert signing_artifacts_state(tmp_path) == (False, False)
    (tmp_path/"sbom").mkdir()
    (tmp_path/"sbom/cosign.pub").write_text("k")
    assert signing_artifacts_state(tmp_path) == (False, True)

def test_committed_signing_artifacts_are_all_or_nothing():
    sig, pub = signing_artifacts_state(_REPO)   # the real repo root
    assert sig == pub, "commit cosign.pub and the .sig together, or neither"

def test_module_imports_nothing_heavy():
    import secure_ai_research.supply_chain.signing  # noqa
    assert "sigstore" not in sys.modules and "cryptography" not in sys.modules
```

- [ ] **Step 2: Run to verify it fails** — `./.venv/bin/pytest tests/test_signing.py -q` → FAIL (module missing).
- [ ] **Step 3: Implement `signing.py`** with the signatures above. `sign_release_sbom` runs `subprocess.run(sign_command(...), cwd=repo_root, capture_output=True, text=True)`, raising `SigningError` (naming only the exit/`FileNotFoundError`, never the key bytes) on failure; `verify_release_sbom` runs `verify_command` over the `_PUB/_SIG/_SBOM` trio and returns True / raises `SigningError`. `signing_artifacts_state` checks `(repo_root/_SIG)` and `(repo_root/_PUB)` exist and are non-empty. `__main__`: `sign_release_sbom(Path.cwd(), os.environ.get("COSIGN_KEY") or sys.argv[1])`.
- [ ] **Step 4: Run to verify it passes** — `./.venv/bin/pytest tests/test_signing.py -q` → PASS.
- [ ] **Step 5: Write the integration test** `tests/test_integration_signing.py` with `pytestmark = pytest.mark.integration` and a `_require_cosign()` helper (`pytest.skip` when `not cosign_available()`): generate a throwaway keypair in `tmp_path` (`cosign generate-key-pair`, blank `COSIGN_PASSWORD`), sign a copy of the committed SBOM → `verify` True; flip one byte → `verify` raises `SigningError`; and, when `signing_artifacts_state(_REPO) == (True, True)`, `verify_release_sbom(_REPO)` is True (the real stale-signature check).
- [ ] **Step 6: Verify the integration test skips cleanly** — `./.venv/bin/pytest -m integration tests/test_integration_signing.py -q` → all **skipped** (cosign absent), 0 errors; and `./.venv/bin/pytest -q -m "not integration" tests/test_integration_signing.py` → deselected/empty. (No production code: the deliverable is a clean-collecting, clean-skipping integration test — ledger this as the verification model for an external-binary test, per the repo's minio/keycloak precedent.)
- [ ] **Step 7: Full gates + commit** — ruff/black/mypy + `./.venv/bin/pytest -q -m "not integration"`; `git add` the two test files + the module; commit.

---

### Task 2: Makefile targets + CI `sbom-verify` job + wiring test

**Files:**
- Modify: `Makefile` (add `sbom-sign`, `sbom-verify`)
- Modify: `.github/workflows/ci.yml` (add the `sbom-verify` job)
- Create: `tests/test_signing_wiring.py` (hermetic, string-level)

**Interfaces — Consumes:** the Task-1 module (`python -m secure_ai_research.supply_chain.signing`).

- [ ] **Step 1: Write the failing wiring test** `tests/test_signing_wiring.py` (reads file text, asserts substrings):

```python
_CI = (_REPO/".github/workflows/ci.yml").read_text()
_MK = (_REPO/"Makefile").read_text()

def test_makefile_has_sign_and_verify_targets():
    assert "\nsbom-sign:" in _MK and "\nsbom-verify:" in _MK

def test_ci_has_sbom_verify_job():
    assert "sbom-verify:" in _CI and "cosign-installer" in _CI

def test_sbom_verify_job_is_public_key_only():
    # no OIDC token minting anywhere in CI (keyed-offline posture)
    assert "id-token" not in _CI

def test_gitignore_blocks_private_keys():
    gi = (_REPO/".gitignore").read_text()
    assert "*.key" in gi and "*.pem" in gi
```

- [ ] **Step 2: Run to verify it fails** — FAIL on the CI/Makefile asserts.
- [ ] **Step 3: Implement** — add Makefile `sbom-sign` (`./.venv/bin/python -m secure_ai_research.supply_chain.signing`) and `sbom-verify` (verify via the module), both in `.PHONY` + `## help` comments. Add the CI `sbom-verify` job: `runs-on: ubuntu-latest`, `permissions: {contents: read}`, checkout@v7, `sigstore/cosign-installer@<pinned ≥2-week-old tag>`, then a step that **skips when `sbom/cosign.pub` or the `.sig` is absent** (shell `if [ -f ... ] && [ -f ... ]`) and otherwise runs `cosign verify-blob --key sbom/cosign.pub --insecure-ignore-tlog=true --signature sbom/release-sbom.cdx.json.sig sbom/release-sbom.cdx.json` (gating).
- [ ] **Step 4: Run to verify it passes** — `tests/test_signing_wiring.py` PASS; `make help` lists both targets; `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` parses (if PyYAML present; else note the real gate is the final CI run).
- [ ] **Step 5: Commit.**

---

### Task 3: Docs + SR-3 evidence

**Files (modify):** `security-controls/supply-chain/sbom.md`, `documentation/sbom/sbom-guide.md`, `documentation/assessment-evidence/control-evidence-matrix.md`, `documentation/system-security-plan/system-security-plan.md`, `README.md`, `architecture/threat-model.md`, `ROADMAP.md`

**Interfaces — Consumes:** Task-1 hermetic node names (for the SR-3 citation).

- [ ] **Step 1: Prove the SR-3 gate is load-bearing** — temporarily add a bogus cited node to the SR-3 row and run `./.venv/bin/pytest -q tests/test_control_evidence.py` → FAIL (uncollectable node); revert the bogus line. (Watch-it-fail for a docs gate.)
- [ ] **Step 2: Update the SR-3 row** in `control-evidence-matrix.md` to add signing: code `src/secure_ai_research/supply_chain/signing.py`; evidence tests = a **hermetic** node (e.g. `tests/test_signing.py::test_sign_command_is_offline` and `tests/test_signing_wiring.py::test_sbom_verify_job_is_public_key_only`) — NOT the `-m integration` node (it won't collect under the gated suite).
- [ ] **Step 3: Update prose docs** — `sbom.md`: the real signature now exists (revise the "SHA-256 pin is the in-posture signed SBOM" wording), keyless/Rekor stays Future work with the tradeoff, add a dated sign-off line + key-management + the private-repo/Rekor identity-leak note + the ceremony steps. `sbom-guide.md`: the sign + verify flow incl. cosign install. `system-security-plan.md`: fix the stale "planned for Slice 7" SR line; add signing. `README.md`: signed, offline-verifiable SBOM. `threat-model.md` T17: add "signed SBOM (cosign, offline-verifiable)". `ROADMAP.md`: tick the signing line.
- [ ] **Step 4: Run the doc-linters + full suite** — `./.venv/bin/pytest -q -m "not integration"` (incl. `test_control_evidence.py` + `test_compliance_docs.py`) green; ruff/black on any touched py unaffected.
- [ ] **Step 5: Commit.**

---

## Self-review notes
- Spec coverage: module+tests (Task 1), Makefile+CI+wiring (Task 2), docs+SR-3 (Task 3) — every design "how" item maps to a task.
- Review Focus: each of the 5 lines has a pinning test in Task 1 or 2 (import-heavy, all-or-nothing, CI-security, gitignore) or is explicitly routed to the CI job / integration test (stale signature).
- Proportion: plan ≈ spec length; code blocks are test assertions + signatures only.
