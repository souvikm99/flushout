# 🧪 Flushout Testing Guide

This guide covers how to run, understand, and extend the Flushout test suite.

---

## Prerequisites

```bash
# 1. Activate the virtual environment
source .venv/bin/activate

# 2. Install the SDK in editable mode
pip install -e sdk/

# 3. Install pytest
pip install pytest
```

---

## Running Tests

### Run all tests
```bash
python -m pytest tests/ -v
```

### Run a specific test file
```bash
python -m pytest tests/test_session.py -v
python -m pytest tests/test_capture.py -v
python -m pytest tests/test_client.py -v
python -m pytest tests/test_integration.py -v
```

### Run a specific test class or method
```bash
python -m pytest tests/test_capture.py::TestTeeWriter -v
python -m pytest tests/test_capture.py::TestTeeWriter::test_thread_safety -v
```

### Run with short traceback (for cleaner output)
```bash
python -m pytest tests/ -v --tb=short
```

### Run with coverage (install `pytest-cov` first)
```bash
pip install pytest-cov
python -m pytest tests/ --cov=flushout --cov-report=term-missing
```

---

## Test Structure

```
tests/
├── __init__.py             # Package marker
├── conftest.py             # Shared fixtures (env var cleanup)
├── test_session.py         # Session ID generation & URL management
├── test_capture.py         # TeeWriter & OutputCapture
├── test_client.py          # LogStreamer HTTP client
└── test_integration.py     # Full stream() context manager pipeline
```

---

## What Each Test File Covers

### `test_session.py` — Session Module (11 tests)

| Test Class | What's Tested |
|---|---|
| `TestGenerateSessionId` | IDs are strings, 8 chars, hex-only, unique across 100 calls |
| `TestGetApiUrl` | Default URL fallback, env var override, trailing slash stripping |
| `TestGetDashboardUrl` | Default URL fallback, env var override |
| `TestPrintSessionUrl` | Returns correct URL, prints with ANSI formatting |

### `test_capture.py` — Capture Module (15 tests)

| Test Class | What's Tested |
|---|---|
| `TestTeeWriter` | Dual output (original + buffer), empty/None writes ignored, flush delegation, encoding property, read/write/seek flags, **thread safety with 5 concurrent writers** |
| `TestOutputCapture` | stdout/stderr interception, stream restoration on stop, drain returns empty when no output, drain clears buffer, idempotent start/stop, context manager protocol |

### `test_client.py` — Client Module (11 tests)

| Test Class | What's Tested |
|---|---|
| `TestLogStreamerInit` | Trailing slash stripping, session ID storage |
| `TestLogStreamerCreateSession` | Correct URL, name in payload, returns False on failure |
| `TestLogStreamerSendLogs` | Correct endpoint, log text in payload |
| `TestLogStreamerFlush` | Drains buffer and POSTs, no-op when buffer empty |
| `TestLogStreamerStartStop` | Background thread lifecycle, end signal sent on stop |

### `test_integration.py` — Integration (5 tests)

| Test | What's Tested |
|---|---|
| `test_stream_yields_session_id` | `stream()` yields a valid 8-char session ID |
| `test_stream_captures_print_output` | `print()` inside stream triggers API calls |
| `test_stream_restores_stdout_after_exit` | stdout is restored after normal exit |
| `test_stream_restores_stdout_on_exception` | stdout is restored even after an exception |
| `test_stream_creates_and_ends_session` | Full create → end lifecycle |

---

## Key Design Decisions

### No real network calls
All tests mock `requests.Session` so they run instantly without needing a running Worker. This makes them:
- **Fast** (~1.6s for all 42 tests)
- **Reliable** (no flaky network failures)
- **CI-friendly** (no external dependencies)

### Environment variable isolation
The `conftest.py` fixture automatically saves and restores `FLUSHOUT_API_URL` and `FLUSHOUT_DASHBOARD_URL` so tests don't leak state.

### Thread safety verification
`test_thread_safety` spawns 5 concurrent writer threads each writing 50 messages, verifying all 250 messages arrive in the buffer without data loss.

---

## Adding New Tests

1. **Create a new test file** in `tests/` prefixed with `test_`.
2. **Use descriptive test classes** grouped by functionality.
3. **Mock external calls** — use `@patch("flushout.client.requests.Session")` for HTTP.
4. **Clean up after yourself** — use the `clean_env` fixture pattern from `conftest.py` if you add new env vars.

Example template:

```python
"""Tests for my_new_module."""

import pytest
from flushout.my_module import my_function


class TestMyFunction:
    def test_basic_case(self):
        result = my_function("input")
        assert result == "expected"

    def test_edge_case(self):
        with pytest.raises(ValueError):
            my_function(None)
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: No module named 'flushout'` | Run `pip install -e sdk/` from the project root |
| `ModuleNotFoundError: No module named 'pytest'` | Run `pip install pytest` |
| Tests pass locally but fail in CI | Make sure the venv is activated and SDK is installed |
| Env var tests are flaky | Check that `conftest.py` is in the `tests/` directory |
