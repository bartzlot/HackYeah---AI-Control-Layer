"""Deterministic detectors (pure functions): text -> hits in ORIGINAL coordinates.

Secrets: AWS access key id + secret, GitHub tokens (CRC32 checked), PEM private keys, JWT,
generic `api_key=` / `token:` assignments, OpenAI-style `sk-` keys.
PII: PESEL (checksum + birth date), IBAN (mod-97), payment card (Luhn), e-mail, phone.
Markings and policy dictionaries for destination DLP.
"""
from __future__ import annotations

import re
from functools import lru_cache
import zlib
from dataclasses import dataclass, field
from datetime import date

from .util import normalized_view, view_span


@dataclass(frozen=True)
class Hit:
    start: int
    end: int
    type: str
    value: str
    score: float = 0.9
    meta: dict = field(default_factory=dict, compare=False, hash=False)


# ------------------------------------------------------------------ secrets

_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _base62(n: int, width: int = 6) -> str:
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = _B62[r] + out
    return out.rjust(width, "0")


def github_crc_ok(token: str) -> bool:
    """GitHub token = prefix_ + 30 random chars + 6-char base62 CRC32 of the random part."""
    body = token.split("_", 1)[1]
    return len(body) == 36 and _base62(zlib.crc32(body[:30].encode())) == body[30:]


def make_github_token(random30: str, prefix: str = "ghp") -> str:
    """Synthetic token with a valid checksum (tests and demo only)."""
    return f"{prefix}_{random30}{_base62(zlib.crc32(random30.encode()))}"


_SECRET_RES: list[tuple[str, re.Pattern[str], int, int]] = [
    # (type, pattern, value group, priority)
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)"), 0, 100),
    ("AWS_KEY", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])"), 0, 100),
    ("AWS_SECRET", re.compile(r"(?i)aws_?secret_?(?:access_?)?key\s*[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), 1, 100),
    ("GITHUB_TOKEN", re.compile(r"(?<![A-Za-z0-9_])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}(?![A-Za-z0-9])"), 0, 100),
    ("GITHUB_TOKEN", re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{60,90}"), 0, 100),
    ("JWT", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), 0, 95),
    ("API_KEY", re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}"), 0, 95),
    ("API_KEY", re.compile(
        r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|token|password|passwd|pwd)"
        r"\b\s*[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=!@#$%^&*]{8,})"), 1, 80),
]

_PLACEHOLDER = re.compile(r"(?i)^(?:x+|\*+|changeme|example|your[_-].*|<.*>|\$\{.*|\{\{.*|null|none|true|false|redacted.*)$")


def find_secrets(text: str, github_crc: str = "prefer") -> list[Hit]:
    hits: list[Hit] = []
    for typ, rx, grp, prio in _SECRET_RES:
        for m in rx.finditer(text):
            s, e = m.span(grp)
            val = m.group(grp)
            score = 0.9
            if typ == "GITHUB_TOKEN" and val.startswith("gh") and "_" in val[:4]:
                ok = github_crc_ok(val)
                if not ok and github_crc == "require":
                    continue
                score = 0.99 if ok else 0.8
            if typ == "API_KEY" and grp == 1:
                if _PLACEHOLDER.match(val) or not (re.search(r"[A-Za-z]", val) and re.search(r"\d", val)):
                    continue
                if text[e:e + 1] in ("(", "["):          # code: token = get_token_v2(x), key = keys[0]
                    continue
                quoted = s > 0 and text[s - 1] in "\"'"
                if not quoted and len(val) < 16:         # unquoted values must look like a real key
                    continue
                score = 0.7
            hits.append(Hit(s, e, typ, val, score, {"priority": prio}))
    return _dedupe(hits)


def _dedupe(hits: list[Hit]) -> list[Hit]:
    """Drop hits fully contained in a higher-or-equal priority hit."""
    hits = sorted(hits, key=lambda h: (-h.meta.get("priority", 50), -(h.end - h.start), h.start))
    out: list[Hit] = []
    for h in hits:
        if any(o.start <= h.start and h.end <= o.end for o in out):
            continue
        out.append(h)
    return sorted(out, key=lambda h: h.start)


# ------------------------------------------------------------------ PII validators

_PESEL_W = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)


def pesel_ok(s: str) -> bool:
    if len(s) != 11 or not s.isdigit():
        return False
    d = [int(c) for c in s]
    if (10 - sum(w * x for w, x in zip(_PESEL_W, d)) % 10) % 10 != d[10]:
        return False
    yy, mm, dd = d[0] * 10 + d[1], d[2] * 10 + d[3], d[4] * 10 + d[5]
    century = {0: 1900, 20: 2000, 40: 2100, 60: 2200, 80: 1800}[(mm // 20) * 20]
    try:
        date(century + yy, mm % 20, dd)
    except ValueError:
        return False
    return True


def make_pesel(y: int, m: int, d: int, serial: int = 123) -> str:
    """Synthetic valid PESEL (tests and demo only)."""
    off = {18: 80, 19: 0, 20: 20, 21: 40, 22: 60}[y // 100]
    base = f"{y % 100:02d}{m + off:02d}{d:02d}{serial:03d}0"
    digits = [int(c) for c in base]
    chk = (10 - sum(w * x for w, x in zip(_PESEL_W, digits)) % 10) % 10
    return base + str(chk)


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for c in reversed(digits):
        n = int(c)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


IBAN_LEN = {"PL": 28, "DE": 22, "GB": 22, "FR": 27, "ES": 24, "IT": 27, "NL": 18, "BE": 16, "CZ": 24, "SK": 24,
            "AT": 20, "CH": 21, "IE": 22, "LT": 20, "LV": 21, "EE": 20, "SE": 24, "NO": 15, "DK": 18, "FI": 18,
            "PT": 25, "UA": 29}


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not (15 <= len(s) <= 34) or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", s):
        return False
    if s[:2] in IBAN_LEN and len(s) != IBAN_LEN[s[:2]]:
        return False
    n = int("".join(str(int(c, 36)) for c in s[4:] + s[:4]))
    return n % 97 == 1


_IBAN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Za-z0-9])")
_PESEL_RE = re.compile(r"(?<!\d)(?<!\d[ -])\d{11}(?!\d)")
# card candidates: canonical groupings first (so a CVV or date after the number cannot hide it), then a
# contiguous 13-19 digit run; a start inside a spaced digit run is never a candidate
_CARD_RES = [re.compile(r"(?<!\d)(?<!\d[ -])\d{4}([ -]?)\d{4}\1\d{4}\1\d{4}(?!\d)"),               # 16 in groups
             re.compile(r"(?<!\d)(?<!\d[ -])3[47]\d{2}([ -]?)\d{6}\1\d{5}(?!\d)"),                 # Amex 15
             re.compile(r"(?<!\d)(?<!\d[ -])\d{13,19}(?!\d)")]
_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?![\w-])")
_PHONE_RE = re.compile(r"(?<![\w+])(?:\+48[ -]?)?\d{3}[ -]\d{3}[ -]\d{3}(?![\w-])|(?<![\w+])\+\d{1,3}(?:[ -]?\d{2,4}){2,4}(?![\w-])")


def _iban_hits(text: str) -> list[Hit]:
    out = []
    for m in _IBAN_RE.finditer(text):
        raw = m.group(0)
        # trim trailing groups until the checksum holds (a following word may have been swallowed)
        cut = len(raw)
        while cut >= 15:
            cand = raw[:cut].rstrip()
            if iban_ok(cand):
                out.append(Hit(m.start(), m.start() + len(cand), "IBAN", cand.replace(" ", ""), 0.95))
                break
            sp = raw.rfind(" ", 0, cut)
            if sp <= 0:
                break
            cut = sp
    return out


def find_pii(text: str, own_domains: list[str] | tuple = ()) -> list[Hit]:
    hits = _iban_hits(text)

    def free(s: int, e: int) -> bool:
        return not any(s < h.end and h.start < e for h in hits)

    for m in _PESEL_RE.finditer(text):
        if free(*m.span()) and pesel_ok(m.group(0)):
            hits.append(Hit(m.start(), m.end(), "PL_PESEL", m.group(0), 0.95))
    for rx in _CARD_RES:
        for m in rx.finditer(text):
            digits = re.sub(r"[ -]", "", m.group(0))
            if free(*m.span()) and 13 <= len(digits) <= 19 and luhn_ok(digits) and digits[0] in "23456":
                hits.append(Hit(m.start(), m.end(), "CREDIT_CARD", digits, 0.9))
    own = {d.lower() for d in own_domains}
    for m in _EMAIL_RE.finditer(text):
        dom = m.group(1).lower()
        internal = dom in own or any(dom.endswith("." + d) for d in own)
        hits.append(Hit(m.start(), m.end(), "EMAIL", m.group(0), 0.9, {"own_domain": internal}))
    for m in _PHONE_RE.finditer(text):
        if free(*m.span()):
            hits.append(Hit(m.start(), m.end(), "PHONE", re.sub(r"[ -]", "", m.group(0)), 0.7))
    return sorted(hits, key=lambda h: h.start)


# ------------------------------------------------------------------ markings and dictionaries

def find_terms(text: str, terms: list[str], typ: str, case_sensitive: bool = False) -> list[Hit]:
    """Whole-word match over the normalized view (diacritics folded, whitespace collapsed, format characters
    dropped); spans map back to the ORIGINAL text through the offset map, so redaction stays exact.
    case_sensitive=True for document markings (CONFIDENTIAL as a label, not "keep this confidential")."""
    if not terms:
        return []
    rx, by_view, probes = _terms_rx(tuple(terms), case_sensitive)
    if text.isascii():      # nothing to fold: if no term can occur, skip building the view (C-speed check)
        hay = text if case_sensitive else text.lower()
        if not any(p in hay for p in probes):
            return []
    view, omap = normalized_view(text)
    hits = []
    for m in rx.finditer(view):
        st, en = view_span(omap, m.start(), m.end(), len(text))
        key = m.group(0) if case_sensitive else m.group(0).lower()
        hits.append(Hit(st, en, typ, text[st:en], 0.9, {"term": by_view.get(key, m.group(0))}))
    return hits


@lru_cache(maxsize=256)
def _terms_rx(terms: tuple[str, ...], case_sensitive: bool):
    """One alternation per term list (longest first), the term per matched view text, and probes: the longest
    ASCII-letter run of each term, for the fast "cannot match" check on ASCII text."""
    views = {}
    for t in terms:
        tv = normalized_view(t)[0].strip()
        if tv:
            views[tv if case_sensitive else tv.lower()] = t
    alts = sorted(views, key=len, reverse=True)
    pat = "|".join(re.escape(v).replace(r"\ ", " ") for v in alts) or "(?!)"
    rx = re.compile(r"(?<!\w)(?:" + pat + r")(?!\w)", 0 if case_sensitive else re.IGNORECASE)
    probes = []
    for v in alts:
        runs = re.findall(r"[A-Za-z]+", v)
        probes.append(max(runs, key=len) if runs else "")
    return rx, views, tuple(p if case_sensitive else p.lower() for p in probes)
