# Flushout

Private, ephemeral Python output streaming. Run a script on one machine and watch its stdout/stderr live from your authenticated web dashboard.

Production dashboard: <https://flushout.online>

**Flushout does not save output.** Log frames exist only in the producer, Cloudflare relay, and connected browser memory while the live WebSockets are open. Late viewers cannot replay earlier output.

## User experience

1. Create/sign into an account on the Flushout website.
2. Choose a unique portal username.
3. Generate and save the show-once permanent streaming password.
4. Install the package and run:

   ```python
   import flushout

   with flushout.stream(name="training-run"):
       print("Training model...")
   ```

5. Enter the portal username and streaming password at the hidden terminal prompts.
6. The named session appears automatically in the dashboard. Tap it to open the responsive live terminal.
7. At the end of an interactive run, optionally email a metadata-only success or failure summary to the verified address in your profile.

The SDK also prints a private `/live/<session-id>` URL. It works only for the signed-in owner.

## Local Python installation

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e sdk
.venv/bin/python tests/print_souvik.py
```

For non-interactive CI only, inject `FLUSHOUT_USERNAME` and `FLUSHOUT_STREAM_PASSWORD` from the CI secret store. Do not commit either value.

## Architecture

```text
Python SDK --WSS--> Cloudflare Worker/Durable Object --WSS--> owner dashboard
                           |
                           `-- HTTPS auth checks --> Supabase Auth + minimal profile
```

- Cloudflare Worker serves the static dashboard and API from one origin.
- One hibernatable Durable Object per authenticated user coordinates live WebSockets.
- Durable Object storage, KV, D1, R2, queues, and disk spooling are not used.
- Supabase contains its managed Auth records and `private.profiles`: user UUID, username, one keyed streaming-password digest, and timestamps.
- The portal discovers enabled Supabase providers and supports GitHub OAuth, Google OAuth, and email/password. Social providers require their provider credentials; production email signup requires custom SMTP. Cloudflare Turnstile protects streaming-password generation.

## Verification

```bash
python -m pip install -r requirements-dev.txt
python -m pip install -e sdk
python -m pytest -q
npm ci --prefix worker
npm test --prefix worker
```

Security issues should be reported privately through this repository's **Security → Report a vulnerability** flow. See [SECURITY.md](SECURITY.md). Never place secrets in issues, discussions, source files, command arguments, or chat.

## Privacy limitations

- Output still traverses Cloudflare infrastructure and appears in browser memory.
- Opt-in completion emails contain run metadata and a bounded exception message, but never streamed output or tracebacks.
- Refreshes, network interruptions, Worker deployments, and reconnects can lose lines.
- Do not stream credentials, private keys, regulated data, or production customer information.
- Free infrastructure has quotas and no application SLA.

## License

MIT
