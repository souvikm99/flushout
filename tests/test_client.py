"""Tests for the ephemeral WebSocket client."""

import json
from unittest.mock import MagicMock, patch

import pytest

from flushout.capture import OutputCapture
from flushout.client import FlushoutConnectionError, LogStreamer, split_utf8, websocket_url
from flushout.session import DEFAULT_API_URL


class FakeResponse:
    def __init__(self, status_code=201, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeSocket:
    def __init__(self, session_id="session-1"):
        self.session_id = session_id
        self.messages = []
        self.closed = False

    def settimeout(self, _timeout):
        pass

    def recv(self):
        return json.dumps({"type": "ready", "session_id": self.session_id})

    def send(self, message):
        self.messages.append(json.loads(message))

    def close(self):
        self.closed = True


def ticket_payload(session_id="session-1"):
    return {"ticket": "signed-ticket", "session_id": session_id, "live_url": f"https://example.test/live/{session_id}"}


def test_default_api_url_is_canonical_production_domain():
    assert DEFAULT_API_URL == "https://flushout.online"


def test_websocket_url_requires_secure_remote_transport():
    assert websocket_url("https://example.test") == "wss://example.test/api/v1/stream"
    assert websocket_url("http://localhost:8787") == "ws://localhost:8787/api/v1/stream"
    with pytest.raises(ValueError):
        websocket_url("http://example.test")
    with pytest.raises(ValueError):
        websocket_url("https://user:password@example.test")
    with pytest.raises(ValueError):
        websocket_url("https://example.test?ticket=secret")


@patch("flushout.client.requests.Session")
def test_insecure_url_is_rejected_before_http_session_or_credentials(mock_session_class):
    with pytest.raises(ValueError, match="HTTPS"):
        LogStreamer("http://example.test", OutputCapture())
    mock_session_class.assert_not_called()


def test_split_utf8_respects_byte_limit_and_codepoints():
    text = "🙂" * 100
    chunks = split_utf8(text, max_bytes=17)
    assert "".join(chunks) == text
    assert all(len(chunk.encode("utf-8")) <= 17 for chunk in chunks)


@patch("flushout.client.websocket.create_connection")
@patch("flushout.client.requests.Session")
def test_connect_uses_ticket_and_authorization_header(mock_session_class, mock_create):
    http = MagicMock()
    http.post.return_value = FakeResponse(payload=ticket_payload())
    mock_session_class.return_value = http
    mock_create.return_value = FakeSocket()
    streamer = LogStreamer("https://example.test", OutputCapture())

    assert streamer.connect("souvik", "secret", "training") == "https://example.test/live/session-1"
    assert http.post.call_args.kwargs["allow_redirects"] is False
    assert http.post.call_args.kwargs["json"]["stream_password"] == "secret"
    assert "Authorization: Bearer signed-ticket" in mock_create.call_args.kwargs["header"]


@patch("flushout.client.websocket.create_connection")
@patch("flushout.client.requests.Session")
def test_bad_credentials_raise_generic_error(mock_session_class, mock_create):
    http = MagicMock()
    http.post.return_value = FakeResponse(status_code=401)
    mock_session_class.return_value = http
    streamer = LogStreamer("https://example.test", OutputCapture())
    with pytest.raises(FlushoutConnectionError, match="invalid username or streaming password"):
        streamer.connect("unknown", "wrong", "training")
    mock_create.assert_not_called()


@patch("flushout.client.websocket.create_connection")
@patch("flushout.client.requests.Session")
def test_flush_sends_ordered_output_without_disk(mock_session_class, mock_create):
    http = MagicMock()
    http.post.return_value = FakeResponse(payload=ticket_payload())
    mock_session_class.return_value = http
    socket = FakeSocket()
    mock_create.return_value = socket
    capture = OutputCapture()
    streamer = LogStreamer("https://example.test", capture)
    streamer.connect("souvik", "secret", "training")
    capture._buffer.append_record("stdout", "hello\n")
    streamer._flush()
    capture._buffer.append_record("stderr", "problem\n")
    streamer._flush()
    outputs = [message for message in socket.messages if message["type"] == "output"]
    assert [message["sequence"] for message in outputs] == [0, 1]
    assert outputs[0]["content"] == "hello\n"


@patch("flushout.client.websocket.create_connection")
@patch("flushout.client.requests.Session")
def test_stop_clears_credentials_and_closes_socket(mock_session_class, mock_create):
    http = MagicMock()
    http.post.return_value = FakeResponse(payload=ticket_payload())
    mock_session_class.return_value = http
    socket = FakeSocket()
    mock_create.return_value = socket
    streamer = LogStreamer("https://example.test", OutputCapture())
    streamer.connect("souvik", "secret", "training")
    streamer.stop()
    assert streamer._username is None
    assert streamer._stream_password is None
    assert socket.closed
    assert socket.messages[-1]["type"] == "session_end"
