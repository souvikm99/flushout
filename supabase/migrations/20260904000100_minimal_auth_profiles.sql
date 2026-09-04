create schema if not exists private;
create schema if not exists api;

revoke all on schema private from public, anon, authenticated;
revoke all on schema api from public, anon, authenticated;
grant usage on schema api to authenticated, service_role;

create table private.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  stream_password_digest bytea,
  stream_password_created_at timestamptz,
  stream_password_revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint profiles_username_format check (username ~ '^[a-z0-9_]{3,32}$'),
  constraint profiles_digest_size check (
    stream_password_digest is null
    or octet_length(stream_password_digest) = 32
  )
);

alter table private.profiles enable row level security;
revoke all on table private.profiles from public, anon, authenticated;

alter default privileges in schema private revoke all on tables from public, anon, authenticated;
alter default privileges in schema private revoke execute on functions from public, anon, authenticated;
alter default privileges in schema api revoke execute on functions from public, anon, authenticated;

create or replace function api.claim_username(requested_username text)
returns table (username text, has_stream_password boolean, stream_password_created_at timestamptz)
language plpgsql
security definer
set search_path = ''
as $$
declare
  caller uuid := auth.uid();
  normalized text := lower(trim(requested_username));
begin
  if caller is null then
    raise exception using errcode = '28000', message = 'authentication required';
  end if;
  if normalized !~ '^[a-z0-9_]{3,32}$' then
    raise exception using errcode = '22023', message = 'invalid username';
  end if;

  insert into private.profiles (user_id, username)
  values (caller, normalized)
  on conflict (user_id) do update
    set username = excluded.username,
        updated_at = now();

  return query
    select p.username,
           p.stream_password_digest is not null and p.stream_password_revoked_at is null,
           p.stream_password_created_at
    from private.profiles p
    where p.user_id = caller;
exception
  when unique_violation then
    raise exception using errcode = '23505', message = 'username unavailable';
end;
$$;

create or replace function api.get_my_profile()
returns table (username text, has_stream_password boolean, stream_password_created_at timestamptz)
language sql
security definer
set search_path = ''
stable
as $$
  select p.username,
         p.stream_password_digest is not null and p.stream_password_revoked_at is null,
         p.stream_password_created_at
  from private.profiles p
  where p.user_id = auth.uid()
    and auth.uid() is not null;
$$;

create or replace function api.set_stream_password(digest_hex text)
returns table (username text, has_stream_password boolean, stream_password_created_at timestamptz)
language plpgsql
security definer
set search_path = ''
as $$
declare
  caller uuid := auth.uid();
begin
  if caller is null then
    raise exception using errcode = '28000', message = 'authentication required';
  end if;
  if digest_hex !~ '^[0-9a-f]{64}$' then
    raise exception using errcode = '22023', message = 'invalid digest';
  end if;

  update private.profiles p
     set stream_password_digest = decode(digest_hex, 'hex'),
         stream_password_created_at = now(),
         stream_password_revoked_at = null,
         updated_at = now()
   where p.user_id = caller;

  if not found then
    raise exception using errcode = 'P0002', message = 'profile required';
  end if;

  return query
    select p.username, true, p.stream_password_created_at
      from private.profiles p
     where p.user_id = caller;
end;
$$;

create or replace function api.revoke_stream_password()
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  caller uuid := auth.uid();
begin
  if caller is null then
    raise exception using errcode = '28000', message = 'authentication required';
  end if;

  update private.profiles p
     set stream_password_digest = null,
         stream_password_revoked_at = now(),
         updated_at = now()
   where p.user_id = caller;
end;
$$;

create or replace function api.verify_stream_login(requested_username text, digest_hex text)
returns table (user_id uuid)
language sql
security definer
set search_path = ''
stable
as $$
  select p.user_id
    from private.profiles p
   where p.username = lower(trim(requested_username))
     and p.stream_password_revoked_at is null
     and p.stream_password_digest is not null
     and digest_hex ~ '^[0-9a-f]{64}$'
     and p.stream_password_digest = decode(digest_hex, 'hex')
   limit 1;
$$;

revoke execute on function api.claim_username(text) from public, anon;
revoke execute on function api.get_my_profile() from public, anon;
revoke execute on function api.set_stream_password(text) from public, anon;
revoke execute on function api.revoke_stream_password() from public, anon;
revoke execute on function api.verify_stream_login(text, text) from public, anon, authenticated;

grant execute on function api.claim_username(text) to authenticated;
grant execute on function api.get_my_profile() to authenticated;
grant execute on function api.set_stream_password(text) to authenticated;
grant execute on function api.revoke_stream_password() to authenticated;
grant execute on function api.verify_stream_login(text, text) to service_role;
