-- Preserve the shared project's existing public and GraphQL API schemas while
-- adding only Flushout's narrow RPC schema.
alter role authenticator set pgrst.db_schemas = 'public, graphql_public, api';
notify pgrst, 'reload config';
