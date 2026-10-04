"""Signed attack-signature feed (PDF section 2: "signatures of such attacks can be fed from some externally
managed system"; research/13 s.11).

Publisher (a threat-intel team, a vendor, CI):
    python -m aicl_gateway.feed keygen feed.key                  -> prints the public key (base64)
    python -m aicl_gateway.feed sign rules.yaml feed.key 7 > bundle.json
Consumer (every gateway): AICL_FEED_URL=<https URL of bundle.json>, AICL_FEED_PUBKEY=<base64 public key>,
AICL_FEED_INTERVAL_S=60. Each poll: Ed25519 signature over (version, sha256(rules)) must verify with the pinned
key; the version must be newer than the active one (no rollback); the rules must load and pass their own inline
match / no_match tests; only then policy/rules/feed.yaml is replaced atomically and the engine reloads. Findings
from these rules carry rule_source "feed". Anything else is rejected and the active rules stay.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from aicl_core.policy import PolicyError, load_rule_file

FEED_FILE = "feed.yaml"


def _message(version: int, rules_yaml: str) -> bytes:
    return f"aicl-feed/1\n{int(version)}\n{hashlib.sha256(rules_yaml.encode('utf-8')).hexdigest()}".encode()


def keygen(path: str | Path) -> str:
    key = Ed25519PrivateKey.generate()
    Path(path).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return public_b64(key)


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def sign(rules_yaml: str, key: Ed25519PrivateKey, version: int) -> dict[str, Any]:
    return {"format": "aicl-feed/1", "version": int(version), "issued": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sha256": hashlib.sha256(rules_yaml.encode("utf-8")).hexdigest(), "rules_yaml": rules_yaml,
            "signature": base64.b64encode(key.sign(_message(version, rules_yaml))).decode()}


class FeedError(Exception):
    pass


def verify(bundle: dict, pubkey_b64: str) -> tuple[int, str]:
    """-> (version, rules_yaml) or FeedError."""
    if not isinstance(bundle, dict) or bundle.get("format") != "aicl-feed/1":
        raise FeedError("not an aicl-feed/1 bundle")
    try:
        version, rules_yaml = int(bundle["version"]), str(bundle["rules_yaml"])
        sig = base64.b64decode(bundle["signature"])
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64))
    except (KeyError, ValueError, TypeError) as e:
        raise FeedError(f"malformed bundle: {e}") from e
    try:
        pub.verify(sig, _message(version, rules_yaml))
    except InvalidSignature as e:
        raise FeedError("signature does not verify with the pinned feed key") from e
    return version, rules_yaml


class FeedPoller:
    """Polls one bundle URL; applies a newer, verified, self-testing rule set to <policy dir>/rules/feed.yaml."""

    def __init__(self, url: str, pubkey_b64: str, policy_path: str | Path, engine=None, interval_s: float = 60.0,
                 fetch: Callable[[str], bytes] | None = None, audit=None):
        self.url, self.pubkey, self.engine, self.interval_s, self.audit = url, pubkey_b64, engine, interval_s, audit
        self.rules_path = Path(policy_path).resolve().parent / "rules" / FEED_FILE
        self.state_path = self.rules_path.with_suffix(".state.json")
        self._fetch = fetch or self._http_get
        self.status: dict[str, Any] = {"url": url, "version": self._active_version(), "last_check": None,
                                       "last_error": None, "rules": None}
        self._stop = threading.Event()

    def _active_version(self) -> int:
        try:
            return int(json.loads(self.state_path.read_text(encoding="utf-8"))["version"])
        except (OSError, ValueError, KeyError):
            return 0

    @staticmethod
    def _http_get(url: str) -> bytes:
        r = httpx.get(url, timeout=10.0, follow_redirects=False)
        r.raise_for_status()
        return r.content

    def poll_once(self) -> str:
        """-> "applied" | "unchanged" | "rejected: <reason>"."""
        self.status["last_check"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            bundle = json.loads(self._fetch(self.url))
            version, rules_yaml = verify(bundle, self.pubkey)
            if version <= self.status["version"]:
                self.status["last_error"] = None
                return "unchanged"
            # the rules must load and pass their own inline tests before they can go live
            with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
                f.write(rules_yaml)
                tmp = Path(f.name)
            try:
                rules = load_rule_file(tmp, source="feed")
            finally:
                tmp.unlink(missing_ok=True)
            self.rules_path.parent.mkdir(parents=True, exist_ok=True)
            part = self.rules_path.with_suffix(".tmp")
            part.write_text(rules_yaml, encoding="utf-8")
            os.replace(part, self.rules_path)
            self.state_path.write_text(json.dumps({"version": version, "sha256": bundle.get("sha256")}), encoding="utf-8")
            self.status.update(version=version, last_error=None, rules=len(rules))
            if self.engine is not None:
                self.engine.store.refresh(force=True)
            return "applied"
        except (FeedError, PolicyError, ValueError, httpx.HTTPError, OSError) as e:
            self.status["last_error"] = f"{type(e).__name__}: {e}"
            return f"rejected: {e}"

    def start(self) -> "FeedPoller":
        def loop():
            while True:
                self.poll_once()
                if self._stop.wait(self.interval_s):
                    return
        threading.Thread(target=loop, name="aicl-feed", daemon=True).start()
        return self

    def stop(self) -> None:
        self._stop.set()


def from_env(env: dict, policy_path: str | Path, engine) -> FeedPoller | None:
    url, pub = env.get("AICL_FEED_URL"), env.get("AICL_FEED_PUBKEY")
    if not url:
        return None
    if not pub:
        raise ValueError("AICL_FEED_URL needs AICL_FEED_PUBKEY: an unsigned feed is never accepted")
    return FeedPoller(url, pub, policy_path, engine, float(env.get("AICL_FEED_INTERVAL_S") or 60)).start()


def main(argv: list[str] | None = None) -> int:
    a = list(sys.argv[1:] if argv is None else argv)
    if a[:1] == ["keygen"] and len(a) == 2:
        print(keygen(a[1]))
        return 0
    if a[:1] == ["sign"] and len(a) == 4:
        key = serialization.load_pem_private_key(Path(a[2]).read_bytes(), password=None)
        print(json.dumps(sign(Path(a[1]).read_text(encoding="utf-8"), key, int(a[3])), indent=1))
        return 0
    print("usage: python -m aicl_gateway.feed keygen <key file> | sign <rules.yaml> <key file> <version>",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
