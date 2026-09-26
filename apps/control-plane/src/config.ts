export interface Config {
  port: number;
  publicUrl: string;
  tenantId: string;
  clientId: string;
  clientSecret: string;
  allowedUserIds: string[];
  allowedTenantUsers: Record<string, string[]>;
  openTenantOnboarding: boolean;
  tokenEncryptionKey: string;
  databaseUrl: string;
  sessionTtlSeconds: number;
  graphScopes: string[];
  /** Optional connectors enabled on this deployment (ONLINE_CONNECTORS). Disabled connectors report "not available". */
  connectors: { azure: boolean; exchange: boolean };
  /** Absolute path of PowerShell 7 for the Exchange Online runner (EXCHANGE_PWSH_PATH). */
  exchangePwshPath: string | null;
}

/**
 * The only delegated Microsoft Graph scopes GRAPH_SCOPES may contain. All are read-only;
 * each maps to datasets in packages/schemas (see docs/ONLINE-WORKLOADS.md).
 */
export const READ_ONLY_GRAPH_SCOPES: readonly string[] = [
  'User.Read',
  'AuditLog.Read.All',
  'Directory.Read.All',
  'Organization.Read.All',
  'Policy.Read.All',
  'RoleManagement.Read.Directory',
  'User.Read.All',
  'UserAuthenticationMethod.Read.All',
  // Directory synchronization settings (delegated only; Microsoft documents Global Administrator as the only supported role)
  'OnPremDirectorySynchronization.Read.All',
  // Microsoft Intune
  'DeviceManagementConfiguration.Read.All',
  'DeviceManagementManagedDevices.Read.All',
  // SharePoint and OneDrive
  'SharePointTenantSettings.Read.All',
  // Microsoft Teams
  'TeamworkAppSettings.Read.All',
  'Team.ReadBasic.All',
];

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const required = (name: string): string => {
    const value = env[name]?.trim();
    if (!value) throw new Error(`Missing required configuration: ${name}`);
    return value;
  };
  const publicUrl = new URL(required('PUBLIC_URL'));
  if (publicUrl.protocol !== 'https:' || publicUrl.username || publicUrl.password || publicUrl.pathname !== '/' || publicUrl.search || publicUrl.hash) throw new Error('PUBLIC_URL must be an HTTPS origin');
  const tenantId = required('AZURE_TENANT_ID').toLowerCase();
  const clientId = required('AZURE_CLIENT_ID').toLowerCase();
  if (env.OPEN_TENANT_ONBOARDING !== undefined && !['true', 'false'].includes(env.OPEN_TENANT_ONBOARDING)) throw new Error('OPEN_TENANT_ONBOARDING must be true or false');
  const openTenantOnboarding = env.OPEN_TENANT_ONBOARDING === 'true';
  if (openTenantOnboarding && env.ALLOWED_TENANT_USERS) throw new Error('Open onboarding cannot be combined with an approved-tenant map');
  const allowedUserIds = env.ALLOWED_TENANT_USERS || openTenantOnboarding ? [] : required('ALLOWED_USER_IDS').split(',').map(value => value.trim().toLowerCase());
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (![tenantId, clientId, ...allowedUserIds].every(value => uuid.test(value))) throw new Error('Tenant, client and allowed user IDs must be UUIDs');
  const allowedTenantUsers: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
  if (env.ALLOWED_TENANT_USERS) {
    let raw: unknown;
    try { raw = JSON.parse(env.ALLOWED_TENANT_USERS) as unknown; } catch { throw new Error('ALLOWED_TENANT_USERS must be a JSON tenant-to-user-ID map'); }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !Object.keys(raw).length) throw new Error('ALLOWED_TENANT_USERS must be a nonempty tenant-to-user-ID map');
    for (const [tenant, users] of Object.entries(raw)) {
      if (!uuid.test(tenant) || !Array.isArray(users) || !users.length || !users.every((user: unknown) => typeof user === 'string' && uuid.test(user))) throw new Error('Each approved tenant must contain a nonempty array of user UUIDs');
      const normalized = tenant.toLowerCase();
      if (allowedTenantUsers[normalized]) throw new Error('Duplicate approved tenant');
      allowedTenantUsers[normalized] = (users as string[]).map(user => user.toLowerCase());
    }
  } else allowedTenantUsers[tenantId] = allowedUserIds;
  const tokenEncryptionKey = required('TOKEN_ENCRYPTION_KEY');
  if (Buffer.from(tokenEncryptionKey, 'base64').length !== 32) throw new Error('TOKEN_ENCRYPTION_KEY must encode 32 random bytes');
  const port = Number(env.PORT ?? '8080');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
  const graphScopes = required('GRAPH_SCOPES').split(/\s+/).filter(scope => scope !== '');
  const readScopes = new Set(READ_ONLY_GRAPH_SCOPES);
  if (!graphScopes.every(scope => readScopes.has(scope.replace(/^https:\/\/graph\.microsoft\.com\//, '')))) throw new Error('GRAPH_SCOPES must contain only supported read-only Microsoft Graph scopes');
  const connectorNames = (env.ONLINE_CONNECTORS ?? '').split(/[\s,]+/).filter(name => name !== '');
  if (!connectorNames.every(name => name === 'azure' || name === 'exchange')) throw new Error('ONLINE_CONNECTORS may contain only "azure" and "exchange"');
  const connectors = { azure: connectorNames.includes('azure'), exchange: connectorNames.includes('exchange') };
  const pwsh = env.EXCHANGE_PWSH_PATH?.trim() || null;
  // An absolute path only: the runner never resolves PowerShell through PATH.
  if (pwsh !== null && !/^(\/[\w.@+-]+)+$|^[A-Za-z]:\\[\w .@+\\-]+$/.test(pwsh)) throw new Error('EXCHANGE_PWSH_PATH must be an absolute path');
  if (connectors.exchange && pwsh === null) throw new Error('EXCHANGE_PWSH_PATH is required when the exchange connector is enabled');
  return {
    port, publicUrl: publicUrl.origin, tenantId, clientId,
    clientSecret: required('AZURE_CLIENT_SECRET'), allowedUserIds: allowedTenantUsers[tenantId] ?? [], allowedTenantUsers, openTenantOnboarding,
    tokenEncryptionKey, databaseUrl: required('DATABASE_URL'), sessionTtlSeconds: 3600,
    graphScopes, connectors, exchangePwshPath: pwsh,
  };
}

export function isApprovedUser(config: Config, tenantId: string, userId: string): boolean {
  if (config.openTenantOnboarding) return isTenantId(tenantId) && isTenantId(userId);
  return config.allowedTenantUsers[tenantId]?.includes(userId) === true;
}

export function isTenantId(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value); }
