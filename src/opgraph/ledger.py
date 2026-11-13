"""Ledger: append-only event log (JSONL) and coverage counts (technique x target)."""

from __future__ import annotations

import contextlib
import json
import os
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any


class Ledger:
    """Records every call, decision, fact, effect and finding transition.

    Events are kept in memory and, if `path` is given, appended to a JSONL file as they happen.
    """

    def __init__(self, path: str | Path | None = None, fsync: bool = False) -> None:
        self.path = Path(path) if path else None
        self.fsync = fsync
        self.events: list[dict[str, Any]] = []
        self.coverage: Counter[tuple[str, str]] = Counter()
        self._lock = threading.Lock()
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self._file = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = self.path.open("a", encoding="utf-8")

    def record(self, event: str, **data: Any) -> dict[str, Any]:
        with self._lock:
            row = {"seq": len(self.events), "ts": time.time(), "event": event, **data}
            self.events.append(row)
            if self._file:
                self._file.write(json.dumps(row, default=str) + "\n")
                self._file.flush()
                if self.fsync:
                    os.fsync(self._file.fileno())
            listeners = list(self._listeners)
        for listener in listeners:
            with contextlib.suppress(Exception):  # an observer must never break the engagement
                listener(dict(row))  # a copy: listeners cannot alter the log
        return row

    def subscribe(self, listener: Callable[[dict[str, Any]], None]) -> Callable[[], None]:
        """Call `listener(event)` for every event (live UIs, telemetry). Returns an unsubscribe function."""
        with self._lock:
            self._listeners.append(listener)

        def unsubscribe() -> None:
            with self._lock:
                if listener in self._listeners:
                    self._listeners.remove(listener)

        return unsubscribe

    def count(self, technique: str, target: str) -> None:
        with self._lock:
            self.coverage[(technique, target)] += 1

    def close(self) -> None:
        with self._lock:
            if self._file:
                self._file.close()
                self._file = None


def read_events(path: str | Path) -> Iterator[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)
