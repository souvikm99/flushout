# Flushout Python SDK

Flushout securely relays Python stdout/stderr to the authenticated owner's live dashboard. Output is ephemeral and is never saved by the service.

```python
import flushout

with flushout.stream(name="training-run"):
    print("Live, not stored")
```

Interactive runs prompt for the portal username and streaming password before capture starts. When the context exits, it also asks whether to email a minimal completion summary to the verified address in your Flushout profile. The email reports success/failure metadata and a bounded exception message; it never includes stdout, stderr, or a traceback.

For unattended runs, choose explicitly:

```python
with flushout.stream(name="nightly-job", notify=True):
    run_job()
```

Alternatively set `FLUSHOUT_NOTIFY=yes`. Notifications require a verified profile email. Notification delivery failures are printed locally and never replace an exception raised by your code.
