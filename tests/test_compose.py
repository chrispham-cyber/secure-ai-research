from pathlib import Path

COMPOSE = Path(__file__).resolve().parent.parent / "docker-compose.yml"


def test_no_floating_latest_images():
    """Every service image is pinned to a concrete tag, never ``:latest``.

    The repository's whole posture is supply-chain integrity (pinned deps, SBOM,
    model-hash verification); a floating image tag silently rolls forward and
    breaks reproducibility, so none is allowed.
    """
    offenders = [
        line.strip()
        for line in COMPOSE.read_text().splitlines()
        if line.strip().startswith("image:") and line.rstrip().endswith(":latest")
    ]
    assert offenders == [], f"pin these images to a concrete tag: {offenders}"
