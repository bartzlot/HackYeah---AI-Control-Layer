"""Performance work must not change detection: the ASCII fast path of normalized_view is byte-for-byte the
slow path (same view, same offset map), and the single-regex find_terms finds what one regex per term did."""
import random
import re

from aicl_core.detect import find_terms
from aicl_core.util import _slow_view, normalized_view, view_span


def test_ascii_fast_path_equals_the_reference_implementation():
    rnd = random.Random(7)
    alphabet = "ab CD\t\n\r  x.,;:-_/\\x0b\x0c\x1c\x1f0123456789"
    for _ in range(400):
        s = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 120)))
        for collapse in (True, False):
            v, m = normalized_view(s, collapse)
            rv, rm = _slow_view(s, collapse)
            assert v == rv and list(m) == rm, repr(s)


def test_non_ascii_still_folds_and_drops_hidden_characters():
    v, m = normalized_view("TAJEMNICA PRZEDSI\u0118BIORSTWA\u200b ze\u0142\uff21")
    assert v == "TAJEMNICA PRZEDSIEBIORSTWA zelA"


def _old_find_terms(text, terms, case_sensitive=False):
    view, omap = _slow_view(text, True)
    out = []
    for t in terms:
        tv = _slow_view(t, True)[0].strip()
        rx = re.compile(r"(?<!\w)" + re.escape(tv).replace(r"\ ", " ") + r"(?!\w)", 0 if case_sensitive else re.I)
        out += [view_span(omap, mm.start(), mm.end(), len(text)) for mm in rx.finditer(view)]
    return sorted(out)


def test_single_regex_find_terms_matches_the_per_term_version():
    terms = ["Acme Bank", "Nordwind", "BLUE PELICAN", "ORION"]
    texts = ["Report for ACME   bank and nordwind.", "orion orions ORION-2", "blue\npelican", "no match here",
             "Acme Bank\u200b and Nordw\u0131nd", "TAJEMNICA PRZEDSIEBIORSTWA"]
    for t in texts:
        got = sorted((h.start, h.end) for h in find_terms(t, terms, "X"))
        assert got == _old_find_terms(t, terms), t
    marks = ["CONFIDENTIAL", "INTERNAL ONLY"]
    assert [h.value for h in find_terms("keep this confidential. CONFIDENTIAL", marks, "M", case_sensitive=True)] == ["CONFIDENTIAL"]


def test_overlapping_terms_are_all_found():
    hits = find_terms("Report on Blue Falcon Nest status", ["Blue Falcon", "Falcon Nest"], "X")
    assert sorted(h.value for h in hits) == ["Blue Falcon", "Falcon Nest"]


def test_huge_parts_are_not_cached():
    from aicl_core import util
    before = util._normalized_view.cache_info().currsize
    v, m = normalized_view("x " * (util.CACHE_MAX_CHARS // 2 + 10))
    assert util._normalized_view.cache_info().currsize == before and len(m) == len(v)
