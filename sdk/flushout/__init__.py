"""Private, ephemeral real-time Python output streaming."""

from contextlib import contextmanager
import sys
import time

from .capture import OutputCapture
from .client import FlushoutConnectionError, LogStreamer
from .notifications import FlushoutNotificationError, notification_requested, send_completion_notification
from .session import get_api_url, print_session_url, prompt_credentials

__version__ = "0.3.0"
__all__ = ["stream", "FlushoutConnectionError", "FlushoutNotificationError"]


@contextmanager
def stream(name=None, api_url=None, username=None, stream_password=None, notify=None):
    """
    Relay stdout/stderr live without storing output.

    Interactive runs prompt for portal username and streaming password before
    capture begins. CI may pass arguments or the FLUSHOUT_USERNAME and
    FLUSHOUT_STREAM_PASSWORD secret environment variables.
    """
    resolved_username, resolved_password = prompt_credentials(username, stream_password)
    resolved_api_url = api_url or get_api_url()
    session_name = name or "python-stream"
    capture = OutputCapture()
    streamer = LogStreamer(api_url=resolved_api_url, capture=capture)
    live_url = streamer.connect(resolved_username, resolved_password, name=name)
    print_session_url(live_url)
    capture.start()
    streamer.start()
    started_at = time.monotonic()
    failure = None
    try:
        yield streamer.session_id
    except BaseException as exc:
        failure = exc
        raise
    finally:
        capture.stop()
        streamer.stop()
        try:
            if notification_requested(notify):
                send_completion_notification(
                    resolved_api_url,
                    resolved_username,
                    resolved_password,
                    streamer.session_id,
                    session_name,
                    "error" if failure is not None else "success",
                    time.monotonic() - started_at,
                    error=failure,
                )
                print("[flushout: completion email sent]")
        except Exception as exc:
            print(f"[flushout: {exc}]", file=sys.stderr)
        resolved_password = None
