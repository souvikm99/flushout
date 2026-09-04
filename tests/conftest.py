"""Shared pytest fixtures for the Flushout test suite."""

import os
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def clean_env():
    """Ensure Flushout env vars don't leak between tests."""
    env_vars = ["FLUSHOUT_API_URL", "FLUSHOUT_USERNAME", "FLUSHOUT_STREAM_PASSWORD", "FLUSHOUT_NOTIFY"]
    saved = {k: os.environ.get(k) for k in env_vars}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
