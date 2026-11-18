#!/usr/bin/env python3
"""Print a blank ResearchRecord template as JSON for an analyst to fill in.

The audit trail (design §5.5) is append-only JSON Lines. This emits one blank
record — required fields present but empty — so an analyst can fill it in and
append it to the log::

    python scripts/new_research_record.py >> audit/research-records.jsonl

Requires the package to be installed (``pip install -e .`` or the devcontainer).
"""

from __future__ import annotations

from datetime import UTC, datetime

from secure_ai_research.audit.record import ResearchRecord


def main() -> int:
    template = ResearchRecord(
        research_id="",
        analyst_id="",
        timestamp=datetime.now(UTC),
        objective="",
        model_id="",
        model_version="",
        prompt_template_version="",
    )
    print(template.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
