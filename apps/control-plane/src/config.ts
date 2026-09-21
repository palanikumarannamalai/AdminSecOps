export interface Config {
  port: number;
  publicUrl: string;
  tenantId: string;
  clientId: string;
  clientSecret: string;
  allowedUserIds: string[];
  tokenEncryptionKey: string;
  databaseUrl: string;
  sessionTtlSeconds: number;
  graphScopes: string[];
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const required = (name: string): string => {
    const value = env[name]?.trim();
    if (!value) throw new Error(`Missing required configuration: ${name}`);
    return value;
  };
  const publicUrl = new URL(required('PUBLIC_URL'));
  if (publicUrl.protocol !== 'https:' || publicUrl.username || publicUrl.password || publicUrl.pathname !== '/' || publicUrl.search || publicUrl.hash) throw new Error('PUBLIC_URL must be an HTTPS origin');
  const tenantId = required('AZURE_TENANT_ID');
  const clientId = required('AZURE_CLIENT_ID');
  const allowedUserIds = required('ALLOWED_USER_IDS').split(',').map(value => value.trim());
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (![tenantId, clientId, ...allowedUserIds].every(value => uuid.test(value))) throw new Error('Tenant, client and allowed user IDs must be UUIDs');
  const tokenEncryptionKey = required('TOKEN_ENCRYPTION_KEY');
  if (Buffer.from(tokenEncryptionKey, 'base64').length !== 32) throw new Error('TOKEN_ENCRYPTION_KEY must encode 32 random bytes');
  const port = Number(env.PORT ?? '8080');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
  return {
    port, publicUrl: publicUrl.origin, tenantId, clientId,
    clientSecret: required('AZURE_CLIENT_SECRET'), allowedUserIds,
    tokenEncryptionKey, databaseUrl: required('DATABASE_URL'), sessionTtlSeconds: 3600,
    graphScopes: required('GRAPH_SCOPES').split(/\s+/),
  };
}
