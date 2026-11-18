# Technical Report — TEMPLATE

> _Scope: PUBLIC / synthetic data only._

> One report per analysis or investigation. Every factual claim cites a source document;
> uncited claims are removed, not softened. The report pairs with the machine-readable
> [research record](../../security-controls/audit/audit-record-schema.md) emitted for the
> same analysis.

- **Title:** _…_
- **Analyst / reviewer:** _…_   **Date:** _…_
- **Research ID:** _(matches the audit record)_

## Objective
_The question this analysis set out to answer._

## Scope & sources
_Which sources were in scope; list the document ids and their `sha256:` hashes._

## Method
_Model and version, prompt-template version, retrieval parameters, tools invoked._

## Findings
_Each finding as a claim **with a citation** to a retrieved document id. No claim without a
source._

## Assessment
_Analyst interpretation, confidence, and caveats — clearly separated from the cited
findings above._

## Conclusion & recommendations
_The accepted conclusion and any recommended actions._

## Validation
_Checks run against the draft (citations present, grounding) and the reviewer's sign-off._
