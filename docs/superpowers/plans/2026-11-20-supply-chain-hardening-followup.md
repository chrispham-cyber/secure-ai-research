# Supply-Chain Hardening Follow-up — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (inline, native). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close the four logged Slice-7 supply-chain items (2 deferred minors + 2 Future-work) without touching the runtime path or the committed release SBOM.

**Architecture:** Extend the pure `supply_chain/sbom.py` lock parser; resolve a documentation ruling for the digest scope; digest-pin the resolvable compose base images behind a new hermetic guard; re-lock `virtualenv` in the dev lock only.

**Tech Stack:** Python 3.12 stdlib, pytest, pip-tools 7.7.0 (`pip-compile`), Docker 29 (`docker buildx imagetools inspect` for digests, dev-time only).

**Spec:** `docs/superpowers/specs/2026-11-20-supply-chain-hardening-followup-design.md`

## Global Constraints

- No new runtime dependency; nothing here is imported on the default runtime path.
- `src/secure_ai_research/retrieval/authz.py` and `research_service.py` stay byte-untouched.
- `requirements.txt`, `sbom/release-sbom.cdx.json`, `sbom/sbom.manifest.json` stay byte-identical (checked by `git diff --exit-code`); `tests/test_sbom.py` stays green.
- Hermetic suite green: `./.venv/bin/pytest -q -m "not integration"`.
- Decisions from the gate: **D1 = document-only** (no second digest); **D2 = add the enforcement guard**.
- No cosign/sigstore signing (out of posture).

## Review Focus

1. **Direct-ref parse vs the real lock** — the extended parser must return the *identical* set for the current all-`==` `requirements.txt`, so the SBOM completeness/drift tests don't move. (Test: Task 1 re-asserts the existing `test_sbom_covers_every_pinned_runtime_dependency` stays green + an all-`==`-unchanged assertion.)
2. **`@` false-positive** — a normal `name==x` line must never be misread as a direct reference (`==` checked before `@`). (Test: Task 1 mixed-line test includes `==` lines.)
3. **Compose guard allowlist is real, not a blanket skip** — the guard must fail on *any* un-pinned image except the single MinIO entry. (Test: Task 3 asserts a synthetic un-pinned, non-allowlisted line fails the check.)
4. **virtualenv bump must not move the runtime lock or SBOM** — dev-only re-lock. (Verification: Task 4 `git diff --exit-code requirements.txt sbom/`.)
5. **Digest form is honored by Docker** — `name:tag@sha256:…` keeps the tag but pins the digest; a malformed digest would silently run the tag. (Test: Task 3 guard requires a well-formed `@sha256:[0-9a-f]{64}`.)

---

### Task 1: Direct-reference completeness in `pinned_requirements`

**Files:**
- Modify: `src/secure_ai_research/supply_chain/sbom.py` (the parse loop in `pinned_requirements`; one-line comment at `sbom_digest` — Minor 2 code side of D1)
- Test: `tests/test_sbom.py`

**Interfaces:**
- Consumes: existing `_normalize`, `pinned_requirements(requirements_path: Path) -> set[str]`.
- Produces: same signature; additionally counts `name @ url` and `-e …#egg=name`.

- [ ] **Step 1: Write the failing test** `test_pinned_requirements_counts_direct_references`

```python
def test_pinned_requirements_counts_direct_references(tmp_path):
    lock = tmp_path / "r.txt"
    lock.write_text(
        "fastapi==0.163.2\n"
        "mypkg @ https://example.com/mypkg-1.0-py3-none-any.whl\n"
        "-e git+https://github.com/x/OtherMod.git#egg=OtherMod\n"
        "--index-url https://pypi.org/simple\n"
    )
    assert pinned_requirements(lock) == {"fastapi", "mypkg", "othermod"}
```

- [ ] **Step 2: Run it, verify FAIL** — `./.venv/bin/pytest -q tests/test_sbom.py::test_pinned_requirements_counts_direct_references`
  Expected: FAIL — returns `{"fastapi"}` (the `@` line skipped by `"==" not in spec`, the `-e` line skipped by `startswith("-")`).

- [ ] **Step 3: Implement.** In the loop: skip blank/`#`. For a line starting with `-`, extract `#egg=<name>` if present (regex `#egg=([A-Za-z0-9._-]+)`), else `continue` (covers `-r`/`-c`/`--hash`/`--index-url`). Otherwise strip the marker; if `==` in spec → name before `==`; elif `@` in spec → name before first `@` (PEP 508 direct reference); else `continue`. Drop `[extras]`, normalize, add. Add a one-line comment at `sbom_digest` stating the projection scope is deliberate (git covers whole-file integrity) — D1 code side.

- [ ] **Step 4: Run to verify PASS** — the new test + `./.venv/bin/pytest -q tests/test_sbom.py` all green (esp. `test_pinned_requirements_ignores_noise`, `test_sbom_covers_every_pinned_runtime_dependency`).

- [ ] **Step 5: Commit** — `git add src/secure_ai_research/supply_chain/sbom.py tests/test_sbom.py && git commit`

---

### Task 2: Digest-scope ruling (Minor 2 / D1 — docs)

**Files:**
- Modify: `security-controls/supply-chain/sbom.md` (SBOM section + the digest explanation)

**Interfaces:** none (documentation only).

- [ ] **Step 1: Edit the doc.** Add a short "What the digest covers" note under the Release-SBOM section: the SHA-256 manifest is a *dependency-drift* pin over the `{name,version,purl}` projection; whole-file integrity of the committed `sbom/` artifacts is provided by git; widening into `license`/`externalReferences` is deliberately avoided (volatile, would flap the gate). This is a ruling, not a TODO.

- [ ] **Step 2: Verify** — `./.venv/bin/pytest -q tests/test_compliance_docs.py` stays green (no TEMPLATE/boilerplate markers introduced).

- [ ] **Step 3: Commit** — `git add security-controls/supply-chain/sbom.md && git commit`

---

### Task 3: Digest-pin compose images + enforcement guard (D2)

**Files:**
- Create: `tests/test_compose_pinning.py`
- Modify: `docker-compose.yml` (4 image lines), `security-controls/supply-chain/sbom.md` (base-images sign-off line)

**Interfaces:**
- Produces: `tests/test_compose_pinning.py::test_compose_images_are_digest_pinned` — a standing hermetic gate (parses the compose file as text, no Docker at test time).

- [ ] **Step 1: Write the failing guard.** Parse `docker-compose.yml` for `image:\s*(\S+)`; for each ref assert it contains `@sha256:` followed by 64 hex, OR its repository (text before `:`/`@`) is in `_ALLOWLIST = {"minio/minio"}`. Allowlist is explicit and asserted non-empty.

```python
_ALLOWLIST = {"minio/minio"}
def test_compose_images_are_digest_pinned():
    refs = _image_refs(COMPOSE)           # list[str]
    assert refs                            # sanity: found images
    for ref in refs:
        repo = ref.split("@", 1)[0].rsplit(":", 1)[0]
        if repo in _ALLOWLIST:
            continue
        assert re.search(r"@sha256:[0-9a-f]{64}$", ref), ref
def test_allowlist_is_not_a_blanket_skip():
    assert _image_refs_unpinned_nonallowlisted("otel/x:1@sha256:bad") # helper proves a bad digest fails
```
(Second test may be expressed as a direct assertion that a crafted un-pinned, non-allowlisted ref fails `_is_pinned`.)

- [ ] **Step 2: Run, verify FAIL** — `./.venv/bin/pytest -q tests/test_compose_pinning.py` — 4 images unpinned ⇒ fail.

- [ ] **Step 3: Resolve digests + pin.** For each of pgvector/pgvector:pg16, ollama/ollama:0.3.6, quay.io/keycloak/keycloak:26.0, otel/opentelemetry-collector-contrib:0.104.0: `docker buildx imagetools inspect <ref>` → take the `Digest:` line → rewrite to `image: <ref>@sha256:<digest>`. MinIO line unchanged + add a comment: digest-pin blocked, image retired (Slice 3), tag-only. Update the sign-off base-images bullet to "4/5 digest-pinned; MinIO tag-only (retired upstream)".

- [ ] **Step 4: Run to verify PASS** — guard green (MinIO allowlisted); `tests/test_compliance_docs.py` green.

- [ ] **Step 5: Commit** — `git add tests/test_compose_pinning.py docker-compose.yml security-controls/supply-chain/sbom.md && git commit`

---

### Task 4: Bump `virtualenv` ≥ 21.14.10 (dev lock only)

**Files:**
- Modify: `requirements-dev.txt` (regenerated), `security-controls/supply-chain/sbom.md` (pip-audit sign-off bullet)

**Interfaces:** none (lockfile + docs).

- [ ] **Step 1: Re-lock.** `./.venv/bin/pip-compile --extra=dev --output-file=requirements-dev.txt --strip-extras --upgrade-package virtualenv pyproject.toml`

- [ ] **Step 2: Verify the bump + invariants.**
  - `grep -E '^virtualenv==' requirements-dev.txt` → version ≥ 21.14.10.
  - `git diff --exit-code requirements.txt sbom/release-sbom.cdx.json sbom/sbom.manifest.json` → **clean** (runtime lock + release SBOM unchanged). If dirty: stop — the bump leaked into runtime.
  - `./.venv/bin/pip-audit -r requirements-dev.txt` (advisory) → the virtualenv PYSEC advisory no longer appears (record output).

- [ ] **Step 3: Update the sign-off** — flip the `pip-audit` bullet `[~]`→`[x]` with the new virtualenv version; drop the "bump via Dependabot" caveat.

- [ ] **Step 4: Full hermetic suite** — `./.venv/bin/pytest -q -m "not integration"` all green (incl. `tests/test_sbom.py`).

- [ ] **Step 5: Commit** — `git add requirements-dev.txt security-controls/supply-chain/sbom.md && git commit`

---

**Final:** whole-branch opus-xhigh review (package via review-package); re-grade by effect; Critical/Important → one TDD fix pass; Minor → ledger. Then merge to `main` local and **push to `origin`** (private).
