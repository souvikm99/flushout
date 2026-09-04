"""Tests for credential prompting and URL configuration."""

import os
from unittest.mock import patch

import pytest

from flushout.session import get_api_url, print_session_url, prompt_credentials


def test_get_api_url_from_environment():
    with patch.dict(os.environ, {"FLUSHOUT_API_URL": "https://example.test/"}):
        assert get_api_url() == "https://example.test"


def test_prompt_credentials_uses_hidden_password_prompt():
    with patch("builtins.input", return_value="souvik") as username_prompt, patch("getpass.getpass", return_value="secret") as password_prompt:
        assert prompt_credentials() == ("souvik", "secret")
    username_prompt.assert_called_once()
    password_prompt.assert_called_once()


def test_prompt_credentials_supports_ci_secret_environment():
    with patch.dict(os.environ, {"FLUSHOUT_USERNAME": "ci_user", "FLUSHOUT_STREAM_PASSWORD": "ci_secret"}, clear=False):
        assert prompt_credentials() == ("ci_user", "ci_secret")


def test_empty_credentials_rejected():
    with patch.dict(os.environ, {}, clear=True), patch("builtins.input", return_value=""), patch("getpass.getpass", return_value=""):
        with pytest.raises(ValueError):
            prompt_credentials()


def test_print_session_url_returns_and_prints_exact_url(capsys):
    url = "https://example.test/live/abc"
    assert print_session_url(url) == url
    assert url in capsys.readouterr().out
