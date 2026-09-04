"""Bounded, in-memory stdout/stderr capture. Output is never written to disk."""

from collections import deque
import sys
import threading


class CaptureBuffer:
    def __init__(self, max_bytes=1_048_576):
        self._records = deque()
        self._bytes = 0
        self._max_bytes = max_bytes
        self._dropped_bytes = 0

    def append_record(self, stream_name, text):
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) > self._max_bytes:
            self._dropped_bytes += len(encoded) - self._max_bytes
            encoded = encoded[-self._max_bytes :]
            text = encoded.decode("utf-8", errors="replace")
        size = len(text.encode("utf-8"))
        self._records.append((stream_name, text, size))
        self._bytes += size
        while self._bytes > self._max_bytes and self._records:
            _, _, removed = self._records.popleft()
            self._bytes -= removed
            self._dropped_bytes += removed

    def drain_records(self):
        records = [(stream, text) for stream, text, _ in self._records]
        dropped = self._dropped_bytes
        self._records.clear()
        self._bytes = 0
        self._dropped_bytes = 0
        return records, dropped


class TeeWriter:
    """Write to the original stream and a shared bounded capture buffer."""

    def __init__(self, original_stream, buffer, lock, stream_name="stdout"):
        self._original = original_stream
        self._buffer = buffer
        self._lock = lock
        self._stream_name = stream_name

    def write(self, text):
        if text:
            self._original.write(text)
            with self._lock:
                if hasattr(self._buffer, "append_record"):
                    self._buffer.append_record(self._stream_name, text)
                else:  # Backward-compatible for file-like integrations.
                    self._buffer.append(text)
        return len(text) if text else 0

    def flush(self):
        self._original.flush()

    def isatty(self):
        return self._original.isatty()

    @property
    def encoding(self):
        return getattr(self._original, "encoding", "utf-8")

    def fileno(self):
        return self._original.fileno()

    def readable(self):
        return False

    def writable(self):
        return True

    def seekable(self):
        return False


class OutputCapture:
    """Capture stdout/stderr in bounded memory while preserving local output."""

    def __init__(self, max_buffer_bytes=1_048_576):
        self._buffer = CaptureBuffer(max_buffer_bytes)
        self._lock = threading.Lock()
        self._original_stdout = None
        self._original_stderr = None
        self._active = False

    def start(self):
        if self._active:
            return
        self._original_stdout = sys.stdout
        self._original_stderr = sys.stderr
        sys.stdout = TeeWriter(self._original_stdout, self._buffer, self._lock, "stdout")
        sys.stderr = TeeWriter(self._original_stderr, self._buffer, self._lock, "stderr")
        self._active = True

    def stop(self):
        if not self._active:
            return
        sys.stdout = self._original_stdout
        sys.stderr = self._original_stderr
        self._active = False

    def drain_records(self):
        with self._lock:
            return self._buffer.drain_records()

    def drain(self):
        records, _ = self.drain_records()
        return "".join(text for _, text in records)

    def notice(self, message):
        target = self._original_stderr or sys.stderr
        target.write(f"\n[flushout: {message}]\n")
        target.flush()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
