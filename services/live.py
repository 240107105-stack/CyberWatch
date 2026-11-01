"""Bounded, polling-based file tailing for a single user-selected local log."""

import os
from pathlib import Path
import uuid


def _read_at(stream, size: int, offset: int) -> bytes:
    """Read an anchor without moving the tail cursor (including on Windows)."""
    pread = getattr(os, "pread", None)
    if callable(pread):
        return pread(stream.fileno(), size, offset)
    position = stream.tell()
    try:
        stream.seek(offset)
        return stream.read(size)
    finally:
        stream.seek(position)


class LogTailer:
    """Read complete newly appended lines, including after rotation/truncation.

    read_new() reads at most max_bytes and emits at most max_lines per call.
    It never starts threads or touches Tkinter/SQLite. A generation-specific
    source_id allows the importer to retain identical events after log rotation.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        from_start: bool = False,
        max_lines: int = 1000,
        max_bytes: int = 262144,
        max_line_bytes: int = 1048576,
    ):
        if min(max_lines, max_bytes, max_line_bytes) < 1:
            raise ValueError("Пределы чтения должны быть положительными")
        self.path = Path(path).expanduser().resolve()
        self.max_lines = max_lines
        self.max_bytes = max_bytes
        self.max_line_bytes = max_line_bytes
        self._session = uuid.uuid4().hex
        self._generation = 0
        self._closed = False
        self._file = None
        self._buffer = bytearray()
        self._dropping = False
        self._drop_initial = False
        self._line_number = 0
        self._pending_change = None
        self._anchor = b""
        self._anchor_offset = 0
        self._open(from_start=from_start)

    def _open(self, *, from_start: bool) -> None:
        new_file = self.path.open("rb", buffering=0)
        stat = os.fstat(new_file.fileno())
        if self._file is not None:
            self._file.close()
        self._file = new_file
        self._identity = (stat.st_dev, stat.st_ino)
        self._buffer.clear()
        self._dropping = False
        self._drop_initial = False
        self._line_number = 0
        self._pending_change = None
        if not from_start:
            self._file.seek(0, os.SEEK_END)
            if self._file.tell() and _read_at(self._file, 1, self._file.tell() - 1) != b"\n":
                self._dropping = True
                self._drop_initial = True
        self.source_id = f"{self.path}#tail:{self._session}:{self._generation}"
        self._remember_anchor()

    def _remember_anchor(self) -> None:
        position = self._file.tell()
        self._anchor_offset = max(0, position - 64)
        self._anchor = _read_at(self._file, position - self._anchor_offset, self._anchor_offset)

    def _refresh_file(self) -> None:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            # Between rename and replacement keep draining the old descriptor.
            return
        position = self._file.tell()
        if self._pending_change == "truncation":
            if b"\n" not in self._buffer:
                self._generation += 1
                self._open(from_start=True)
            return
        if (stat.st_dev, stat.st_ino) != self._identity:
            # A bounded previous read may have complete old lines in _buffer,
            # or leave readable data on the renamed descriptor. Never discard
            # them or mix two source_id generations in one returned batch.
            old_size = os.fstat(self._file.fileno()).st_size
            if b"\n" not in self._buffer and position >= old_size:
                self._generation += 1
                self._open(from_start=True)
            else:
                self._pending_change = "rotation"
            return
        rewritten = self._anchor and _read_at(
            self._file, len(self._anchor), self._anchor_offset
        ) != self._anchor
        if stat.st_size < position or rewritten:
            if b"\n" not in self._buffer:
                self._generation += 1
                self._open(from_start=True)
            else:
                # The remaining buffer is already from the old generation;
                # after truncation the descriptor's unread bytes are not.
                self._pending_change = "truncation"
        else:
            self._pending_change = None

    def read_new(self) -> list[tuple[int, str]]:
        if self._closed:
            raise ValueError("Наблюдение за файлом уже остановлено")
        self._refresh_file()
        results = []
        bytes_read = 0
        processed_lines = 0
        while processed_lines < self.max_lines:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(self._buffer[:newline + 1])
                del self._buffer[:newline + 1]
                self._line_number += 1
                processed_lines += 1
                if self._dropping or len(raw) > self.max_line_bytes:
                    if not self._drop_initial:
                        results.append((self._line_number, ""))
                    self._dropping = self._drop_initial = False
                else:
                    results.append((self._line_number, raw.decode("utf-8", errors="replace")))
                continue
            if len(self._buffer) > self.max_line_bytes:
                self._buffer.clear()
                self._dropping = True
            if self._pending_change == "truncation":
                break
            if bytes_read >= self.max_bytes:
                break
            chunk = self._file.read(min(65536, self.max_bytes - bytes_read))
            if not chunk:
                break
            bytes_read += len(chunk)
            self._buffer.extend(chunk)
        self._remember_anchor()
        return results

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._file.close()
            self._buffer.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
