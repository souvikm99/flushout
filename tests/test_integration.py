"""Integration behavior around the public stream context manager."""

import sys
from unittest.mock import MagicMock, patch

import pytest

import flushout


@patch("flushout.LogStreamer")
def test_stream_prompts_connects_before_capture_and_restores_stdout(mock_streamer_class):
    streamer = MagicMock()
    streamer.connect.return_value = "https://example.test/live/session-1"
    streamer.session_id = "session-1"
    mock_streamer_class.return_value = streamer
    original_stdout = sys.stdout

    with patch("flushout.prompt_credentials", return_value=("souvik", "secret")):
        with flushout.stream(name="test", api_url="https://example.test") as session_id:
            assert session_id == "session-1"
            print("hello")

    assert sys.stdout is original_stdout
    streamer.connect.assert_called_once_with("souvik", "secret", name="test")
    streamer.start.assert_called_once()
    streamer.stop.assert_called_once()


@patch("flushout.LogStreamer")
def test_stream_restores_stdout_when_user_code_raises(mock_streamer_class):
    streamer = MagicMock()
    streamer.connect.return_value = "https://example.test/live/session-1"
    streamer.session_id = "session-1"
    mock_streamer_class.return_value = streamer
    original_stdout = sys.stdout
    with patch("flushout.prompt_credentials", return_value=("souvik", "secret")):
        with pytest.raises(ValueError):
            with flushout.stream(api_url="https://example.test"):
                raise ValueError("boom")
    assert sys.stdout is original_stdout
    streamer.stop.assert_called_once()


@patch("flushout.send_completion_notification")
@patch("flushout.LogStreamer")
def test_stream_sends_opted_in_success_notification(mock_streamer_class, mock_notify):
    streamer = MagicMock(session_id="12345678-1234-1234-1234-123456789abc")
    streamer.connect.return_value = "https://example.test/live/session-1"
    mock_streamer_class.return_value = streamer
    with patch("flushout.prompt_credentials", return_value=("souvik", "secret")):
        with flushout.stream(name="training", api_url="https://example.test", notify=True):
            pass
    assert mock_notify.call_args.args[5] == "success"
    assert mock_notify.call_args.kwargs["error"] is None


@patch("flushout.send_completion_notification")
@patch("flushout.LogStreamer")
def test_notification_failure_never_masks_user_exception(mock_streamer_class, mock_notify, capsys):
    streamer = MagicMock(session_id="12345678-1234-1234-1234-123456789abc")
    streamer.connect.return_value = "https://example.test/live/session-1"
    mock_streamer_class.return_value = streamer
    mock_notify.side_effect = RuntimeError("email unavailable")
    with patch("flushout.prompt_credentials", return_value=("souvik", "secret")):
        with pytest.raises(ValueError, match="original failure"):
            with flushout.stream(api_url="https://example.test", notify=True):
                raise ValueError("original failure")
    assert "email unavailable" in capsys.readouterr().err
    assert mock_notify.call_args.args[5] == "error"
    assert isinstance(mock_notify.call_args.kwargs["error"], ValueError)
