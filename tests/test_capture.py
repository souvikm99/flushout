"""Tests for the OutputCapture and TeeWriter modules."""

import sys
import threading
import io
import pytest

from flushout.capture import OutputCapture, TeeWriter


class TestTeeWriter:
    """Tests for the TeeWriter class."""

    def test_write_to_original_and_buffer(self):
        """TeeWriter should write to both the original stream and the buffer."""
        original = io.StringIO()
        buffer = []
        lock = threading.Lock()
        tee = TeeWriter(original, buffer, lock)

        tee.write("hello world")

        assert original.getvalue() == "hello world"
        assert buffer == ["hello world"]

    def test_empty_write_is_ignored(self):
        """Empty strings should not be written to either destination."""
        original = io.StringIO()
        buffer = []
        lock = threading.Lock()
        tee = TeeWriter(original, buffer, lock)

        tee.write("")

        assert original.getvalue() == ""
        assert buffer == []

    def test_none_write_is_ignored(self):
        """None should not be written to either destination."""
        original = io.StringIO()
        buffer = []
        lock = threading.Lock()
        tee = TeeWriter(original, buffer, lock)

        tee.write(None)

        assert original.getvalue() == ""
        assert buffer == []

    def test_flush_delegates_to_original(self):
        """Flush should call flush on the original stream."""
        original = io.StringIO()
        buffer = []
        lock = threading.Lock()
        tee = TeeWriter(original, buffer, lock)

        # Should not raise
        tee.flush()

    def test_encoding_property_with_real_stream(self):
        """Should return encoding from a stream that has one."""
        buffer = []
        lock = threading.Lock()
        tee = TeeWriter(sys.stdout, buffer, lock)

        # sys.stdout has a real encoding (e.g. 'utf-8')
        assert tee.encoding is not None
        assert isinstance(tee.encoding, str)

    def test_writable_and_not_readable(self):
        """TeeWriter should report as writable but not readable."""
        original = io.StringIO()
        buffer = []
        lock = threading.Lock()
        tee = TeeWriter(original, buffer, lock)

        assert tee.writable() is True
        assert tee.readable() is False
        assert tee.seekable() is False

    def test_thread_safety(self):
        """Multiple threads writing concurrently should not lose data."""
        original = io.StringIO()
        buffer = []
        lock = threading.Lock()
        tee = TeeWriter(original, buffer, lock)

        def writer(msg, count):
            for _ in range(count):
                tee.write(msg)

        threads = [
            threading.Thread(target=writer, args=(f"t{i}-", 50))
            for i in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Each thread writes 50 messages → 250 total
        assert len(buffer) == 250


class TestOutputCapture:
    """Tests for the OutputCapture class."""

    def test_captures_stdout(self, capsys):
        """OutputCapture should intercept stdout and buffer it."""
        capture = OutputCapture()
        capture.start()
        try:
            print("captured line", end="")
            text = capture.drain()
            assert text == "captured line"
        finally:
            capture.stop()

    def test_captures_stderr(self):
        """OutputCapture should intercept stderr and buffer it."""
        capture = OutputCapture()
        capture.start()
        try:
            sys.stderr.write("error line")
            text = capture.drain()
            assert text == "error line"
        finally:
            capture.stop()

    def test_restores_streams_on_stop(self):
        """stop() should restore original stdout and stderr."""
        original_stdout = sys.stdout
        original_stderr = sys.stderr

        capture = OutputCapture()
        capture.start()
        assert sys.stdout is not original_stdout
        assert sys.stderr is not original_stderr

        capture.stop()
        assert sys.stdout is original_stdout
        assert sys.stderr is original_stderr

    def test_drain_returns_empty_when_no_output(self):
        """drain() should return empty string when nothing has been captured."""
        capture = OutputCapture()
        capture.start()
        try:
            text = capture.drain()
            assert text == ""
        finally:
            capture.stop()

    def test_drain_clears_buffer(self):
        """drain() should clear the buffer after returning content."""
        capture = OutputCapture()
        capture.start()
        try:
            print("first", end="")
            first = capture.drain()
            assert first == "first"

            # Second drain should be empty
            second = capture.drain()
            assert second == ""
        finally:
            capture.stop()

    def test_multiple_start_is_idempotent(self):
        """Calling start() multiple times should be safe."""
        capture = OutputCapture()
        capture.start()
        capture.start()  # Should not raise or double-wrap
        try:
            print("test", end="")
            text = capture.drain()
            assert text == "test"
        finally:
            capture.stop()

    def test_multiple_stop_is_idempotent(self):
        """Calling stop() multiple times should be safe."""
        capture = OutputCapture()
        capture.start()
        capture.stop()
        capture.stop()  # Should not raise

    def test_context_manager(self):
        """OutputCapture can be used as a context manager."""
        with OutputCapture() as cap:
            print("ctx managed", end="")
            text = cap.drain()
            assert text == "ctx managed"

    def test_buffer_is_bounded_and_reports_drops(self):
        capture = OutputCapture(max_buffer_bytes=10)
        capture._buffer.append_record("stdout", "12345678")
        capture._buffer.append_record("stdout", "abcdefgh")
        records, dropped = capture.drain_records()
        assert sum(len(text.encode("utf-8")) for _, text in records) <= 10
        assert dropped >= 8
