"""In-process audit bus: fan-out of AuditRecord to SSE subscribers (dashboard)."""
from __future__ import annotations

import asyncio
import json
from collections import deque


class Subscription:
    def __init__(self, bus: "EventBus", maxsize: int):
        self._bus = bus
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)

    def __aiter__(self):
        return self

    async def __anext__(self):
        item = await self.queue.get()
        if item is None:
            raise StopAsyncIteration
        return item

    def close(self) -> None:
        self._bus._subs.discard(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        self.close()


class EventBus:
    """publish(dict) from the gateway; subscribe() yields dicts; sse() yields SSE text frames."""

    def __init__(self, history: int = 500, queue_size: int = 1000):
        self._subs: set[Subscription] = set()
        self._queue_size = queue_size
        self.history: deque[dict] = deque(maxlen=history)

    def subscribe(self) -> Subscription:
        sub = Subscription(self, self._queue_size)
        self._subs.add(sub)
        return sub

    def publish(self, record: dict) -> None:
        self.history.append(record)
        for sub in list(self._subs):
            if sub.queue.full():  # slow consumer: drop oldest
                try:
                    sub.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            sub.queue.put_nowait(record)

    def recent(self, n: int = 100) -> list[dict]:
        return list(self.history)[-n:]

    def close(self) -> None:
        for sub in list(self._subs):
            sub.queue.put_nowait(None)

    async def sse(self, replay: int = 0):
        """Async generator of SSE frames; optionally replays the last `replay` records first."""
        sub = self.subscribe()
        try:
            if replay:
                for rec in self.recent(replay):
                    yield f"data: {json.dumps(rec)}\n\n"
            async for rec in sub:
                yield f"data: {json.dumps(rec)}\n\n"
        finally:
            sub.close()
