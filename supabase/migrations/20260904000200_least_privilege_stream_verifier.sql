-- The verifier receives only a Worker-generated HMAC-SHA-256 digest. Keeping
-- this one capability RPC callable by anon avoids giving Cloudflare the broad
-- Supabase secret/service-role key, which is especially important when the
-- selected Supabase project also contains unrelated application tables.
grant usage on schema api to anon;
revoke execute on function api.verify_stream_login(text, text) from service_role;
grant execute on function api.verify_stream_login(text, text) to anon;
