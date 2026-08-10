import { describe, expect, it } from 'vitest';

import {
  ApiServiceConfigurationError,
  parseMongoApiServiceEnvironment,
} from '../src/service-environment.js';

describe('Mongo API service environment', () => {
  it('uses production-safe loopback and disabled-bootstrap defaults', () => {
    expect(
      parseMongoApiServiceEnvironment({
        KAVRIX_MONGODB_URI: 'mongodb://127.0.0.1:27017/?replicaSet=rs0',
      }),
    ).toEqual({
      server: {
        mongodbUri: 'mongodb://127.0.0.1:27017/?replicaSet=rs0',
        databaseName: 'kavrix',
        environment: 'production',
        host: '127.0.0.1',
        port: 3_000,
        vaultBootstrapEnabled: false,
      },
      shutdownTimeoutMs: 15_000,
    });
  });

  it('parses every documented override without coercing ambiguous values', () => {
    expect(
      parseMongoApiServiceEnvironment({
        KAVRIX_MONGODB_URI: 'mongodb+srv://example.invalid/kavrix',
        KAVRIX_DATABASE_NAME: 'vault_data',
        KAVRIX_API_ENVIRONMENT: 'development',
        KAVRIX_API_HOST: '0.0.0.0',
        KAVRIX_API_PORT: '8080',
        KAVRIX_API_TRUSTED_PROXIES: '192.0.2.10, 2001:db8::1,10.0.0.0/8',
        KAVRIX_API_BODY_LIMIT_BYTES: '1048576',
        KAVRIX_API_BOOTSTRAP_ENABLED: 'true',
        KAVRIX_API_SHUTDOWN_TIMEOUT_MS: '30000',
      }),
    ).toEqual({
      server: {
        mongodbUri: 'mongodb+srv://example.invalid/kavrix',
        databaseName: 'vault_data',
        environment: 'development',
        host: '0.0.0.0',
        port: 8_080,
        trustedProxy: ['192.0.2.10', '2001:db8::1', '10.0.0.0/8'],
        bodyLimit: 1_048_576,
        vaultBootstrapEnabled: true,
      },
      shutdownTimeoutMs: 30_000,
    });
  });

  it.each([
    [{}, 'KAVRIX_MONGODB_URI'],
    [{ KAVRIX_MONGODB_URI: 'not-a-uri' }, 'KAVRIX_MONGODB_URI'],
    [{ KAVRIX_MONGODB_URI: 'mongodb://localhost\ninvalid' }, 'KAVRIX_MONGODB_URI'],
    [
      { KAVRIX_MONGODB_URI: 'mongodb://localhost', KAVRIX_API_PORT: '3000.5' },
      'KAVRIX_API_PORT',
    ],
    [
      {
        KAVRIX_MONGODB_URI: 'mongodb://localhost',
        KAVRIX_API_TRUSTED_PROXIES: 'proxy.example.com',
      },
      'KAVRIX_API_TRUSTED_PROXIES',
    ],
    [
      {
        KAVRIX_MONGODB_URI: 'mongodb://localhost',
        KAVRIX_API_TRUSTED_PROXIES: '0.0.0.0/0',
      },
      'KAVRIX_API_TRUSTED_PROXIES',
    ],
    [
      {
        KAVRIX_MONGODB_URI: 'mongodb://localhost',
        KAVRIX_API_TRUSTED_PROXIES: '192.0.2.1/24/extra',
      },
      'KAVRIX_API_TRUSTED_PROXIES',
    ],
    [
      {
        KAVRIX_MONGODB_URI: 'mongodb://localhost',
        KAVRIX_API_TRUSTED_PROXIES: '192.0.2.0/not-a-prefix',
      },
      'KAVRIX_API_TRUSTED_PROXIES',
    ],
    [
      {
        KAVRIX_MONGODB_URI: 'mongodb://localhost',
        KAVRIX_API_TRUSTED_PROXIES: '2001:db8::/129',
      },
      'KAVRIX_API_TRUSTED_PROXIES',
    ],
    [
      {
        KAVRIX_MONGODB_URI: 'mongodb://localhost',
        KAVRIX_API_BOOTSTRAP_ENABLED: 'TRUE',
      },
      'KAVRIX_API_BOOTSTRAP_ENABLED',
    ],
    [
      { KAVRIX_MONGODB_URI: 'mongodb://localhost', KAVRIX_API_P0RT: '3000' },
      'KAVRIX_API_*',
    ],
    [
      {
        KAVRIX_MONGODB_URI: 'mongodb://localhost',
        KAVRIX_API_SHUTDOWN_TIMEOUT_MS: '99',
      },
      'KAVRIX_API_SHUTDOWN_TIMEOUT_MS',
    ],
  ])(
    'rejects invalid or unknown service input without echoing it',
    (environment, setting) => {
      let caught: unknown;
      try {
        parseMongoApiServiceEnvironment(environment);
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(ApiServiceConfigurationError);
      expect(caught).toMatchObject({ setting });
      expect(String(caught)).not.toContain(String(Object.values(environment).at(-1)));
    },
  );
});
