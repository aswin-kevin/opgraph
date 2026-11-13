"""Owned cleanup: everything an engagement creates gets an undo, unwound in reverse order."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager


class EffectStack:
    """A stack of cleanup frames. `phase()` opens a frame that is cleaned when the phase exits;
    `dispose()` cleans everything. Cleanup never raises: failures become RESIDUE lines."""

    def __init__(self) -> None:
        self._frames: list[tuple[str, list[tuple[str, Callable[[], object]]]]] = [("root", [])]
        self._lock = threading.Lock()
        self.history: list[str] = []  # every cleanup line ever produced

    def push(self, label: str, undo: Callable[[], object], root: bool = False) -> None:
        """Own a cleanup. `root=True` ties it to the whole engagement instead of the current phase."""
        with self._lock:
            self._frames[0 if root else -1][1].append((label, undo))

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        with self._lock:
            self._frames.append((name, []))
            depth = len(self._frames)
        try:
            yield
        finally:
            with self._lock:
                frames = self._frames[depth - 1 :]
                del self._frames[depth - 1 :]
            self._unwind(frames)

    def dispose(self) -> list[str]:
        """Undo everything still owned, newest first. Safe to call more than once."""
        with self._lock:
            frames = self._frames
            self._frames = [("root", [])]
        return self._unwind(frames)

    def pending(self) -> list[str]:
        with self._lock:
            return [label for _, effects in self._frames for label, _ in effects]

    @property
    def residue(self) -> list[str]:
        return [line for line in self.history if line.startswith("RESIDUE")]

    def _unwind(self, frames: list[tuple[str, list[tuple[str, Callable[[], object]]]]]) -> list[str]:
        lines = []
        for _, effects in reversed(frames):
            for label, undo in reversed(effects):
                try:
                    undo()
                    lines.append(f"cleaned  {label}")
                except Exception as exc:
                    lines.append(f"RESIDUE  {label}: {type(exc).__name__}: {exc}")
        with self._lock:
            self.history.extend(lines)
        return lines
