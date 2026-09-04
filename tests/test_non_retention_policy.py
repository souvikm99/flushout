"""Static release guards for Flushout's no-output-storage promise."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_supabase_creates_only_the_minimal_profile_table():
    migration = (ROOT / "supabase/migrations/20260904000100_minimal_auth_profiles.sql").read_text()
    tables = re.findall(r"create\s+table\s+([a-z_][a-z0-9_.]*)", migration, flags=re.IGNORECASE)
    assert tables == ["private.profiles"]


def test_profile_table_has_no_output_or_session_payload_columns():
    migration = (ROOT / "supabase/migrations/20260904000100_minimal_auth_profiles.sql").read_text()
    table_body = re.search(
        r"create\s+table\s+private\.profiles\s*\((.*?)\n\);",
        migration,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert table_body
    assert not re.search(
        r"^\s*(output|content|payload|log|logs|history|session|session_id)\s+",
        table_body.group(1),
        flags=re.IGNORECASE | re.MULTILINE,
    )


def test_application_code_has_no_disk_spool_or_cloudflare_storage_binding():
    sources = [
        ROOT / "worker/src/index.js",
        ROOT / "sdk/flushout/capture.py",
        ROOT / "sdk/flushout/client.py",
    ]
    combined = "\n".join(path.read_text() for path in sources)
    forbidden = ["ctx.storage", "state.storage", "env.LOG_KV", "env.OUTPUT_R2", "sqlite3.connect"]
    for marker in forbidden:
        assert marker not in combined


def test_notification_lookup_requires_stream_credential_and_confirmed_email():
    migration = (ROOT / "supabase/migrations/20260904000500_notification_recipient.sql").read_text()
    assert "stream_password_digest = decode(digest_hex, 'hex')" in migration
    assert "email_confirmed_at is not null" in migration
    assert "grant execute on function api.get_notification_recipient(text, text) to anon" in migration
