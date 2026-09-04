"""Configuration and terminal prompting for Flushout sessions."""

import getpass
import os


DEFAULT_API_URL = "https://flushout.online"


def get_api_url():
    return os.environ.get("FLUSHOUT_API_URL", DEFAULT_API_URL).rstrip("/")


def prompt_credentials(username=None, stream_password=None):
    resolved_username = username or os.environ.get("FLUSHOUT_USERNAME")
    resolved_password = stream_password or os.environ.get("FLUSHOUT_STREAM_PASSWORD")
    if not resolved_username:
        resolved_username = input("Flushout username: ").strip()
    if not resolved_password:
        resolved_password = getpass.getpass("Streaming password: ")
    if not resolved_username or not resolved_password:
        raise ValueError("Flushout username and streaming password are required")
    return resolved_username, resolved_password


def print_session_url(url):
    print(f"\n\033[1;36mFlushout live:\033[0m \033[4;37m{url}\033[0m\n")
    return url
