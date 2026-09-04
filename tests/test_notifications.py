"""Completion notification behavior and privacy boundaries."""

from unittest.mock import MagicMock, patch

import pytest

from flushout.notifications import (
    FlushoutNotificationError,
    notification_requested,
    send_completion_notification,
)


def response(status=202, payload=None):
    result = MagicMock(status_code=status)
    result.json.return_value = payload or {"sent": True}
    return result


def test_notification_choice_supports_explicit_and_environment_values():
    assert notification_requested(True) is True
    assert notification_requested(False) is False
    with patch.dict("os.environ", {"FLUSHOUT_NOTIFY": "yes"}):
        assert notification_requested() is True
    with patch.dict("os.environ", {"FLUSHOUT_NOTIFY": "no"}):
        assert notification_requested() is False


def test_noninteractive_notification_defaults_off():
    with patch("sys.stdin.isatty", return_value=False), patch.dict("os.environ", {}, clear=True):
        assert notification_requested() is False


@patch("flushout.notifications.requests.post")
def test_completion_payload_contains_metadata_but_never_output(mock_post):
    mock_post.return_value = response()
    send_completion_notification(
        "https://example.test",
        "souvik",
        "secret",
        "12345678-1234-1234-1234-123456789abc",
        "training",
        "error",
        2.5,
        error=ValueError("boom"),
    )
    payload = mock_post.call_args.kwargs["json"]
    assert payload["status"] == "error"
    assert payload["error_type"] == "ValueError"
    assert payload["error_message"] == "boom"
    assert not {"output", "stdout", "stderr", "traceback"}.intersection(payload)
    assert mock_post.call_args.kwargs["allow_redirects"] is False


@patch("flushout.notifications.requests.post")
def test_missing_verified_email_has_actionable_error(mock_post):
    mock_post.return_value = response(
        409,
        {"error": {"code": "verified_email_required"}},
    )
    with pytest.raises(FlushoutNotificationError, match="add and verify"):
        send_completion_notification(
            "https://example.test",
            "souvik",
            "secret",
            "12345678-1234-1234-1234-123456789abc",
            "training",
            "success",
            1,
        )
