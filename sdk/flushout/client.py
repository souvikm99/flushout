"""Ephemeral WebSocket client for the Flushout relay."""

import json
import ssl
import threading
import time
from urllib.parse import urlparse, urlunparse

import requests
import websocket


MAX_CONTENT_BYTES = 60_000


class FlushoutConnectionError(RuntimeError):
    """Raised when a live stream cannot be authenticated or connected."""


def websocket_url(api_url):
    parsed = urlparse(api_url.rstrip("/"))
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("invalid Flushout API URL")
    if parsed.scheme == "https":
        scheme = "wss"
    elif parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        scheme = "ws"
    else:
        raise ValueError("Flushout requires HTTPS outside local development")
    return urlunparse((scheme, parsed.netloc, "/api/v1/stream", "", "", ""))


def split_utf8(text, max_bytes=MAX_CONTENT_BYTES):
    """Split text without cutting UTF-8 code points."""
    if len(text.encode("utf-8")) <= max_bytes:
        return [text]
    chunks = []
    current = []
    current_bytes = 0
    for character in text:
        size = len(character.encode("utf-8"))
        if current and current_bytes + size > max_bytes:
            chunks.append("".join(current))
            current = []
            current_bytes = 0
        current.append(character)
        current_bytes += size
    if current:
        chunks.append("".join(current))
    return chunks


class LogStreamer:
    """Authenticate once, then relay a bounded in-memory output stream."""

    def __init__(self, api_url, capture, flush_interval=0.5, timeout=10):
        self._api_url = api_url.rstrip("/")
        # Validate transport before credentials can ever be submitted over HTTP.
        self._socket_url = websocket_url(self._api_url)
        self._capture = capture
        self._flush_interval = max(0.1, float(flush_interval))
        self._timeout = timeout
        self._http = requests.Session()
        self._http.headers.update({"Content-Type": "application/json", "User-Agent": "flushout-python/0.3.0"})
        self._socket = None
        self._thread = None
        self._stop_event = threading.Event()
        self._sequence = 0
        self._username = None
        self._stream_password = None
        self._name = None
        self.session_id = None
        self.live_url = None

    def _ticket(self):
        response = self._http.post(
            f"{self._api_url}/api/v1/stream-ticket",
            json={"username": self._username, "stream_password": self._stream_password, "session_name": self._name},
            timeout=self._timeout,
            allow_redirects=False,
        )
        if response.status_code == 401:
            raise FlushoutConnectionError("invalid username or streaming password")
        if response.status_code == 429:
            raise FlushoutConnectionError("too many authentication attempts; try again later")
        if response.status_code >= 400:
            raise FlushoutConnectionError(f"relay rejected connection ({response.status_code})")
        try:
            payload = response.json()
            return payload["ticket"], payload["session_id"], payload["live_url"]
        except (ValueError, KeyError) as exc:
            raise FlushoutConnectionError("relay returned an invalid response") from exc

    def _open_socket(self):
        ticket, session_id, live_url = self._ticket()
        parsed = urlparse(self._api_url)
        socket = websocket.create_connection(
            self._socket_url,
            timeout=self._timeout,
            header=[f"Authorization: Bearer {ticket}"],
            origin=f"{parsed.scheme}://{parsed.netloc}",
            enable_multithread=True,
            sslopt={"cert_reqs": ssl.CERT_REQUIRED},
        )
        socket.settimeout(self._timeout)
        try:
            ready = json.loads(socket.recv())
        except Exception as exc:
            socket.close()
            raise FlushoutConnectionError("relay did not confirm the live session") from exc
        if ready.get("type") != "ready" or ready.get("session_id") != session_id:
            socket.close()
            raise FlushoutConnectionError("relay returned a mismatched session")
        self._socket = socket
        self.session_id = session_id
        self.live_url = live_url

    def connect(self, username, stream_password, name=None):
        self._username = username
        self._stream_password = stream_password
        self._name = name or "python-stream"
        self._open_socket()
        return self.live_url

    def start(self):
        if not self._socket:
            raise FlushoutConnectionError("connect must succeed before capture starts")
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="flushout-sender", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self._timeout)
        self._flush()
        if self._socket:
            try:
                self._socket.send(json.dumps({"type": "session_end"}))
            except Exception:
                self._capture.notice("final session marker could not be delivered")
            finally:
                self._socket.close()
        self._socket = None
        self._stream_password = None
        self._username = None
        self._http.close()

    def _run(self):
        while not self._stop_event.wait(self._flush_interval):
            self._flush()

    def _flush(self):
        records, dropped = self._capture.drain_records()
        if dropped:
            records.insert(0, ("mixed", f"[flushout: {dropped} bytes dropped from remote stream]\n"))
        if not records:
            return
        streams = {stream for stream, _ in records}
        stream = next(iter(streams)) if len(streams) == 1 else "mixed"
        text = "".join(value for _, value in records)
        for chunk in split_utf8(text):
            if not self._send_chunk(stream, chunk):
                self._capture.notice("remote output was lost after the connection closed")
                return

    def _send_chunk(self, stream, content):
        if not self._socket:
            return False
        message = json.dumps({"type": "output", "sequence": self._sequence, "stream": stream, "content": content}, ensure_ascii=False)
        try:
            self._socket.send(message)
            self._sequence += 1
            return True
        except Exception:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
            return False
