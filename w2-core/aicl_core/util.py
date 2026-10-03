"""Shared helpers for controls."""
from __future__ import annotations

import hashlib
import unicodedata
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


def normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(_ZW)
