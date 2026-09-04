-- Resolve a completion-notification recipient only after the caller proves
-- possession of the user's streaming credential digest. The email address is
-- returned only when Supabase Auth has confirmed it.
create or replace function api.get_notification_recipient(requested_username text, digest_hex text)
returns table (user_id uuid, notification_email text)
language sql
security definer
set search_path = ''
stable
as $$
  select p.user_id,
         case when u.email_confirmed_at is not null then u.email else null end
    from private.profiles p
    join auth.users u on u.id = p.user_id
   where p.username = lower(trim(requested_username))
     and p.stream_password_revoked_at is null
     and p.stream_password_digest is not null
     and digest_hex ~ '^[0-9a-f]{64}$'
     and p.stream_password_digest = decode(digest_hex, 'hex')
   limit 1;
$$;

revoke execute on function api.get_notification_recipient(text, text) from public, authenticated, service_role;
grant execute on function api.get_notification_recipient(text, text) to anon;
