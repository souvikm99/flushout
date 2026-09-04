"""Opt-in completion notifications that never include captured output."""

import os
import sys

import requests


class FlushoutNotificationError(RuntimeError):
    """Raised when a requested completion notification cannot be sent."""


def notification_requested(value=None):
    """Resolve an explicit value, environment setting, or interactive prompt."""
    if isinstance(value, bool):
        return value
    configured = os.environ.get("FLUSHOUT_NOTIFY")
    if configured is not None:
        normalized = configured.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off", ""}:
            return False
        raise ValueError("FLUSHOUT_NOTIFY must be yes/true/1 or no/false/0")
    if not sys.stdin.isatty():
        return False
    return input("Email a completion summary to your verified profile email? [y/N]: ").strip().lower() in {"y", "yes"}


def send_completion_notification(
    api_url,
    username,
    stream_password,
    session_id,
    session_name,
    status,
    duration_seconds,
    error=None,
    timeout=10,
):
    """Send metadata-only completion details through the Flushout API."""
    payload = {
        "username": username,
        "stream_password": stream_password,
        "session_id": session_id,
        "session_name": session_name or "python-stream",
        "status": status,
        "duration_seconds": round(max(0.0, float(duration_seconds)), 3),
    }
    if error is not None:
        payload["error_type"] = type(error).__name__[:120]
        payload["error_message"] = str(error)[:1000]
    response = requests.post(
        f"{api_url.rstrip('/')}/api/v1/notifications/completion",
        json=payload,
        timeout=timeout,
        allow_redirects=False,
        headers={"User-Agent": "flushout-python/0.3.0"},
    )
    try:
        body = response.json()
    except ValueError:
        body = {}
    if response.status_code == 409 and body.get("error", {}).get("code") == "verified_email_required":
        raise FlushoutNotificationError(
            "add and verify an email address in your Flushout profile before enabling completion notifications"
        )
    if response.status_code == 401:
        raise FlushoutNotificationError("notification authentication failed")
    if response.status_code == 429:
        raise FlushoutNotificationError("notification rate limit reached; try again later")
    if response.status_code >= 400:
        raise FlushoutNotificationError("completion email could not be sent")
    return True
