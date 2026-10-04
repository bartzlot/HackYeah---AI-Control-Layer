"""T-123 demo batch from the terminal: preset prompts, each caught by a different control, one results table.

    uv run python scripts/demo_batch.py [--url http://localhost:18080] [--key $AICL_KEY_DEMO] [--json]

Needs the stack running (make demo-local / make up) and cloud-sim's demo script for the tool presets.
The audit records of each request are read from the host-only console API (loopback).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

import httpx

from aicl_gateway.demo_batch import render, run_batch


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AICL demo batch")
    ap.add_argument("--url", default=f"http://localhost:{os.environ.get('AICL_GATEWAY_PORT') or '18080'}")
    ap.add_argument("--key", default=os.environ.get("AICL_KEY_DEMO"))
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    a = ap.parse_args(argv)
    if not a.key:
        print("set AICL_KEY_DEMO or pass --key (see .env.example)", file=sys.stderr)
        return 2

    async def go():
        async with httpx.AsyncClient(base_url=a.url, timeout=120) as c:
            async def lookup(rid: str) -> list[dict]:
                r = await c.get("/console/api/events", params={"limit": 100, "request_id": rid})
                r.raise_for_status()
                return r.json()["events"]
            cat = None
            try:
                from aicl_gateway.names import Catalog
                cat = Catalog()
            except Exception:  # noqa: BLE001
                pass
            return await run_batch(c, a.key, lookup, catalog=cat)

    result = asyncio.run(go())
    print(json.dumps(result, indent=2) if a.json else render(result))
    return 0 if all(r["ok"] for r in result["rows"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
