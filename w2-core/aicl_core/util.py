"""Shared helpers for controls."""
from __future__ import annotations

import hashlib
import re
import unicodedata
from array import array
from functools import lru_cache
from collections.abc import Iterator
from typing import Any

from aicl_contracts import Event, Span, Stage

_ZW = dict.fromkeys([0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD], None)   # zero-width, BOM, soft hyphen


def sha8(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:8]


def span(part: int, start: int, end: int, typ: str, value: str) -> Span:
    return Span(part=part, start=start, end=end, type=typ, sha256_8=sha8(value))


def flatten_strings(x: Any) -> list[str]:
    if isinstance(x, str):
        return [x]
    if isinstance(x, dict):
        return [s for v in x.values() for s in flatten_strings(v)]
    if isinstance(x, (list, tuple)):
        return [s for v in x for s in flatten_strings(v)]
    return []


def is_untrusted(event: Event, part_index: int) -> bool:
    p = event.parts[part_index]
    return (not p.trusted) or p.role == "tool" or event.stage == Stage.TOOL_RESULT


def iter_texts(event: Event, include_tool_args: bool = True) -> Iterator[tuple[int, str]]:
    """(part index, text). Tool call i is part -(i+1): its spans cannot be redacted in place."""
    for i, p in enumerate(event.parts):
        yield i, p.text
    if include_tool_args:
        for i, tc in enumerate(event.tool_calls):
            t = "\n".join(flatten_strings(tc.arguments))
            if t:
                yield -(i + 1), t


_L_STROKE = {0x0141: "L", 0x0142: "l"}          # l with stroke has no NFKD decomposition


_WS_RUN = re.compile(r"\s{2,}")
_WS = re.compile(r"\s")


@lru_cache(maxsize=48)
def normalized_view(text: str, collapse_ws: bool = True) -> tuple[str, "array[int]"]:
    """Scan view of `text` with an offset map (omap[j] = index in the ORIGINAL text of view char j):
    format characters (category Cf: zero-width, bidi marks, word joiners) dropped, Unicode tag characters
    decoded to ASCII as a separate word, NFKC + diacritics folded (also l with stroke), whitespace runs
    collapsed to one space. Map a view match [a, b) back with (omap[a], omap[b - 1] + 1).
    Memoized (every control of one decision shares one view per part; coding-agent prompts are ~400 KB),
    and pure-ASCII text, which has nothing to fold or drop, takes a C-speed path with the same result."""
    if text.isascii():
        return _ascii_view(text, collapse_ws)
    v, m = _slow_view(text, collapse_ws)
    return v, array("q", m)


def _ascii_view(text: str, collapse_ws: bool) -> tuple[str, "array[int]"]:
    if not collapse_ws:
        return text, array("q", range(len(text)))
    omap: array = array("q")
    parts: list[str] = []
    pos = 0
    for m in _WS_RUN.finditer(text):
        s, e = m.span()
        omap.extend(range(pos, s + 1))
        parts.append(text[pos:s])
        parts.append(" ")
        pos = e
    omap.extend(range(pos, len(text)))
    parts.append(text[pos:])
    return _WS.sub(" ", "".join(parts)), omap


def _slow_view(text: str, collapse_ws: bool) -> tuple[str, list[int]]:
    out: list[str] = []
    omap: list[int] = []
    in_tags = False
    for i, c in enumerate(text):
        o = ord(c)
        tag = 0xE0020 <= o <= 0xE007E
        if not tag and (o in _ZW or unicodedata.category(c) == "Cf" or 0xFE00 <= o <= 0xFE0F):
            continue
        if tag != in_tags and out and out[-1] != " ":   # a hidden tag run is its own word
            out.append(" ")
            omap.append(i)
        in_tags = tag
        if tag:
            n = chr(o - 0xE0000)
        elif o in _L_STROKE:
            n = _L_STROKE[o]
        else:
            n = "".join(ch for ch in unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", c))
                        if not unicodedata.combining(ch))
        for ch in n:
            if collapse_ws and ch.isspace():
                if out and out[-1] == " ":
                    continue
                ch = " "
            out.append(ch)
            omap.append(i)
    return "".join(out), omap


def view_span(omap: list[int], a: int, b: int, text_len: int) -> tuple[int, int]:
    """View match [a, b) -> original [start, end)."""
    if not omap:
        return 0, 0
    s = omap[a] if a < len(omap) else text_len
    e = omap[b - 1] + 1 if b > a else s
    return s, e
