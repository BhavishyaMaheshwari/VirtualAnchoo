"""Bounded WebSocket fanout: slow consumers cannot stall packet capture.

Both the cross-thread pending queue and each client queue have hard limits.
REST remains the durable source of truth when a browser misses an event.
"""
import asyncio
from collections import deque
import threading
from fastapi import WebSocket

class EventHub:
    def __init__(self):
        self.loop = None
        self.clients = set()
        self.dropped_events = 0
        self.pending = deque(maxlen=1024)
        self.lock = threading.Lock()
        self.scheduled = False

    def bind(self):
        self.loop = asyncio.get_running_loop()

    def publish(self, kind, data):
        with self.lock:
            if not self.loop or self.loop.is_closed():
                return
            if len(self.pending) == self.pending.maxlen:
                self.dropped_events += 1
            self.pending.append({"type":kind,"data":data})
            if not self.scheduled:
                self.scheduled = True
                self.loop.call_soon_threadsafe(self._drain)

    def _drain(self):
        with self.lock:
            events = list(self.pending)
            self.pending.clear()
            self.scheduled = False
        for event in events:
            for queue in tuple(self.clients):
                if queue.full():
                    try:
                        queue.get_nowait()
                        self.dropped_events += 1
                    except asyncio.QueueEmpty:
                        pass
                queue.put_nowait(event)

    async def connect(self, ws: WebSocket):
        await ws.accept()
        queue = asyncio.Queue(maxsize=256)
        self.clients.add(queue)
        return queue

    def disconnect(self, queue):
        self.clients.discard(queue)
