import {
  fieldDefinitionSchema,
  groupTemplateSchema,
  isSensitiveFieldType,
  type BuiltInTemplateKey,
  type FieldDefinition,
  type FieldType,
  type GroupTemplate,
} from '@kavrix/schemas';

import { ValidationError } from './errors.js';

const BUILT_IN_TIMESTAMP = '1970-01-01T00:00:00.000Z';

type FieldOverrides = Partial<
  Pick<
    FieldDefinition,
    | 'required'
    | 'sensitive'
    | 'repeatable'
    | 'copyable'
    | 'searchableLocally'
    | 'showInPreview'
    | 'environmentVariableName'
    | 'selectOptions'
  >
>;

function field(
  templateKey: BuiltInTemplateKey,
  stableKey: string,
  label: string,
  type: FieldType,
  sortOrder: number,
  overrides: FieldOverrides = {},
): FieldDefinition {
  const sensitive = overrides.sensitive ?? isSensitiveFieldType(type);
  return fieldDefinitionSchema.parse({
    id: `builtin.${templateKey}.${stableKey}`,
    stableKey,
    label,
    type,
    required: overrides.required ?? false,
    sensitive,
    repeatable: overrides.repeatable ?? false,
    copyable: overrides.copyable ?? true,
    searchableLocally: overrides.searchableLocally ?? !sensitive,
    showInPreview: overrides.showInPreview ?? !sensitive,
    ...(overrides.environmentVariableName === undefined
      ? {}
      : { environmentVariableName: overrides.environmentVariableName }),
    ...(overrides.selectOptions === undefined
      ? {}
      : { selectOptions: overrides.selectOptions }),
    copyPolicy: sensitive ? 'allowed' : 'allowed',
    revealPolicy: sensitive ? 'timed' : 'never',
    reauthenticationPolicy: sensitive ? 'after-lock' : 'never',
    exportPolicy: sensitive ? 'guarded' : 'encrypted-only',
    sortOrder,
    createdAt: BUILT_IN_TIMESTAMP,
    updatedAt: BUILT_IN_TIMESTAMP,
  });
}

function template(
  key: BuiltInTemplateKey,
  name: string,
  description: string,
  fields: readonly FieldDefinition[],
): GroupTemplate {
  return groupTemplateSchema.parse({
    id: `builtin.${key}`,
    name,
    description,
    builtInKey: key,
    version: 1,
    fields,
    createdAt: BUILT_IN_TIMESTAMP,
    updatedAt: BUILT_IN_TIMESTAMP,
  });
}

const emailFields = [
  field('email', 'email', 'Email address', 'email', 0, { required: true }),
  field('email', 'username', 'Username', 'username', 1),
  field('email', 'password', 'Password', 'secret', 2, { required: true }),
  field('email', 'provider_url', 'Provider URL', 'url', 3),
  field('email', 'recovery_email', 'Recovery email', 'email', 4),
  field('email', 'recovery_phone', 'Recovery phone', 'phone', 5),
  field('email', 'totp_secret', 'TOTP secret', 'totp-secret', 6),
  field('email', 'backup_codes', 'Backup codes', 'recovery-code-list', 7, {
    repeatable: true,
  }),
  field('email', 'app_passwords', 'App passwords', 'secret', 8, { repeatable: true }),
  field('email', 'account_id', 'Account ID', 'text', 9),
  field('email', 'expires_at', 'Expiration', 'datetime', 10),
  field('email', 'rotation_interval_days', 'Rotation interval', 'number', 11),
];

const databaseFields = [
  field('database', 'engine', 'Engine', 'select', 0, {
    required: true,
    selectOptions: ['MongoDB', 'PostgreSQL', 'MySQL', 'Other'].map((value) => ({
      value: value.toLowerCase(),
      label: value,
    })),
  }),
  field('database', 'environment', 'Environment', 'text', 1),
  field('database', 'host', 'Host', 'host', 2, { required: true }),
  field('database', 'port', 'Port', 'port', 3),
  field('database', 'database_name', 'Database name', 'database-name', 4),
  field('database', 'username', 'Username', 'username', 5),
  field('database', 'password', 'Password', 'secret', 6),
  field('database', 'connection_string', 'Connection string', 'connection-string', 7),
  field('database', 'service_name', 'Replica set or service name', 'text', 8),
  field('database', 'tls_mode', 'TLS mode', 'text', 9),
  field('database', 'ca_certificate', 'CA certificate', 'certificate', 10),
  field('database', 'client_certificate', 'Client certificate', 'certificate', 11),
  field('database', 'client_private_key', 'Client private key', 'private-key', 12),
  field('database', 'ssh_tunnel', 'SSH tunnel credential', 'item-reference', 13),
];

const apiFields = [
  field('api-oauth', 'base_url', 'Base URL', 'url', 0),
  field('api-oauth', 'documentation_url', 'Documentation URL', 'url', 1),
  field('api-oauth', 'client_id', 'Client ID', 'client-id', 2),
  field('api-oauth', 'client_secret', 'Client secret', 'client-secret', 3),
  field('api-oauth', 'api_key', 'API key', 'api-key', 4),
  field('api-oauth', 'access_token', 'Access token', 'access-token', 5),
  field('api-oauth', 'refresh_token', 'Refresh token', 'refresh-token', 6),
  field('api-oauth', 'token_endpoint', 'Token endpoint', 'url', 7),
  field('api-oauth', 'scopes', 'Scopes', 'tags', 8),
  field('api-oauth', 'expires_at', 'Expiration', 'datetime', 9),
  field('api-oauth', 'rotation_interval_days', 'Rotation interval', 'number', 10),
  field('api-oauth', 'environment', 'Environment', 'text', 11),
];

const serverFields = [
  field('server-ssh', 'host', 'Host', 'host', 0, { required: true }),
  field('server-ssh', 'port', 'Port', 'port', 1),
  field('server-ssh', 'username', 'Username', 'username', 2),
  field('server-ssh', 'password', 'Password', 'secret', 3),
  field('server-ssh', 'private_key', 'Private key', 'private-key', 4),
  field('server-ssh', 'private_key_passphrase', 'Private-key passphrase', 'secret', 5),
  field('server-ssh', 'public_key', 'Public key', 'public-key', 6),
  field('server-ssh', 'host_fingerprint', 'Host fingerprint', 'text', 7),
  field('server-ssh', 'jump_host', 'Bastion or jump host', 'item-reference', 8),
  field('server-ssh', 'sudo_password', 'Sudo password', 'secret', 9),
  field('server-ssh', 'environment', 'Environment', 'text', 10),
];

const cloudFields = [
  field('cloud-provider', 'provider', 'Provider', 'text', 0, { required: true }),
  field('cloud-provider', 'account_id', 'Account, tenant, or project ID', 'text', 1),
  field('cloud-provider', 'access_key_id', 'Access-key ID', 'client-id', 2),
  field('cloud-provider', 'secret_access_key', 'Secret-access key', 'client-secret', 3),
  field('cloud-provider', 'session_token', 'Session token', 'access-token', 4),
  field('cloud-provider', 'region', 'Region', 'text', 5),
  field('cloud-provider', 'role_identifier', 'Role identifier', 'text', 6),
  field('cloud-provider', 'console_url', 'Console URL', 'url', 7),
  field('cloud-provider', 'totp_secret', 'MFA / TOTP', 'totp-secret', 8),
  field(
    'cloud-provider',
    'recovery_information',
    'Recovery information',
    'secure-multiline',
    9,
  ),
];

const gitFields = [
  field('git-source-control', 'provider', 'Provider', 'text', 0),
  field('git-source-control', 'username_email', 'Username or email', 'text', 1),
  field(
    'git-source-control',
    'personal_access_token',
    'Personal access token',
    'access-token',
    2,
  ),
  field('git-source-control', 'ssh_private_key', 'SSH private key', 'private-key', 3),
  field('git-source-control', 'ssh_passphrase', 'SSH passphrase', 'secret', 4),
  field('git-source-control', 'organization', 'Organization', 'text', 5),
  field('git-source-control', 'repository_url', 'Repository URL', 'url', 6),
  field('git-source-control', 'token_scopes', 'Token scopes', 'tags', 7),
  field('git-source-control', 'expires_at', 'Expiration', 'datetime', 8),
];

const applicationFields = [
  field('application-environment', 'application_name', 'Application name', 'text', 0, {
    required: true,
  }),
  field('application-environment', 'environment', 'Environment', 'text', 1),
  field(
    'application-environment',
    'environment_variables',
    'Environment variables',
    'environment-map',
    2,
    { sensitive: true },
  ),
  field('application-environment', 'deployment_url', 'Deployment URL', 'url', 3),
  field(
    'application-environment',
    'service_account',
    'Service-account credentials',
    'secure-multiline',
    4,
  ),
  field('application-environment', 'signing_secret', 'Signing secret', 'secret', 5),
  field(
    'application-environment',
    'encryption_secret',
    'Encryption secret',
    'secret',
    6,
  ),
  field('application-environment', 'webhook_secret', 'Webhook secret', 'secret', 7),
  field(
    'application-environment',
    'database_credential',
    'Related database credential',
    'item-reference',
    8,
  ),
  field(
    'application-environment',
    'api_credential',
    'Related API credential',
    'item-reference',
    9,
  ),
];

const licenseFields = [
  field('software-license', 'product', 'Product', 'text', 0, { required: true }),
  field('software-license', 'license_key', 'License key', 'secret', 1),
  field('software-license', 'registered_email', 'Registered email', 'email', 2),
  field('software-license', 'organization', 'Organization', 'text', 3),
  field('software-license', 'seat_count', 'Seat count', 'number', 4),
  field('software-license', 'purchase_date', 'Purchase date', 'date', 5),
  field('software-license', 'renewal_date', 'Renewal date', 'date', 6),
  field('software-license', 'vendor_url', 'Vendor URL', 'url', 7),
  field('software-license', 'invoice_reference', 'Invoice or reference', 'text', 8),
];

const secureNoteFields = [
  field('secure-note', 'content', 'Secure content', 'secure-multiline', 0, {
    required: true,
  }),
  field('secure-note', 'tags', 'Tags', 'tags', 1),
  field('secure-note', 'attachments', 'Attachments', 'attachment', 2, {
    repeatable: true,
  }),
  field('secure-note', 'expires_at', 'Expiration', 'datetime', 3),
];

const templateDefinitions: GroupTemplate[] = [
  template(
    'email',
    'Email Account',
    'Email credentials, recovery methods, and rotation metadata.',
    emailFields,
  ),
  template(
    'database',
    'Database',
    'Database connectivity, TLS material, and optional tunnel references.',
    databaseFields,
  ),
  template(
    'api-oauth',
    'API / OAuth Service',
    'API and OAuth client credentials and token lifecycle fields.',
    apiFields,
  ),
  template(
    'server-ssh',
    'Server / SSH / SFTP',
    'Server access and SSH authentication material.',
    serverFields,
  ),
  template(
    'cloud-provider',
    'Cloud Provider',
    'Cloud account, role, access, MFA, and recovery material.',
    cloudFields,
  ),
  template(
    'git-source-control',
    'Git / Source Control',
    'Source-control credentials, keys, and token metadata.',
    gitFields,
  ),
  template(
    'application-environment',
    'Application Environment',
    'Application secrets and related service references.',
    applicationFields,
  ),
  template(
    'software-license',
    'Software License',
    'License ownership, renewal, and secret key information.',
    licenseFields,
  ),
  template(
    'secure-note',
    'Secure Note',
    'Encrypted free-form content with tags and attachments.',
    secureNoteFields,
  ),
  template('custom', 'Custom', 'An empty schema ready for custom fields.', []),
];

for (const definition of templateDefinitions) {
  for (const definitionField of definition.fields) {
    if (definitionField.selectOptions !== undefined) {
      Object.freeze(definitionField.selectOptions);
    }
    Object.freeze(definitionField);
  }
  Object.freeze(definition.fields);
  Object.freeze(definition);
}

export const builtInTemplates: readonly GroupTemplate[] =
  Object.freeze(templateDefinitions);

export function getBuiltInTemplate(key: BuiltInTemplateKey): GroupTemplate {
  const result = builtInTemplates.find((candidate) => candidate.builtInKey === key);
  if (result === undefined)
    throw new ValidationError('The built-in template key is invalid.');
  return groupTemplateSchema.parse(result);
}
