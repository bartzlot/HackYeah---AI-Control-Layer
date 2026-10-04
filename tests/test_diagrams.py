"""docs/diagrams: every mermaid source has a light and a dark SVG, rendered as plain SVG text (no drift, no broken escapes)."""
from pathlib import Path

import pytest

DIR = Path(__file__).resolve().parents[1] / "docs" / "diagrams"
SOURCES = sorted(DIR.glob("*.mmd"))


def test_diagram_set_present():
    assert len(SOURCES) >= 4


@pytest.mark.parametrize("src", SOURCES, ids=lambda p: p.name)
def test_rendered_pair(src: Path):
    for mode in ("light", "dark"):
        svg = src.with_name(f"{src.stem}.{mode}.svg")
        assert svg.is_file(), f"{svg.name} missing: run `make diagrams`"
        text = svg.read_text(encoding="utf-8")
        assert text.lstrip().startswith("<svg"), svg.name
        assert "foreignObject" not in text, f"{svg.name}: htmlLabels must stay off (viewers without HTML)"
        assert "&amp;lt;" not in text and "&amp;gt;" not in text, f"{svg.name}: double-escaped < or > in a label"
        assert "\u2014" not in text and "\u2013" not in text, f"{svg.name}: em/en dash"


def test_every_svg_has_a_source():
    for svg in DIR.glob("*.svg"):
        stem = svg.name.rsplit(".", 2)[0]
        assert (DIR / f"{stem}.mmd").is_file(), f"{svg.name} has no .mmd source"


def test_readme_images_exist():
    import re
    root = DIR.parents[1]
    refs = re.findall(r'(?:src|srcset)="([^"]+)"', (root / "README.md").read_text(encoding="utf-8"))
    assert refs, "README references no images"
    for ref in refs:
        assert (root / ref).is_file(), f"README references missing {ref}"
