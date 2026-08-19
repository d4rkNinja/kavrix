import { describe, expect, it } from 'vitest';

import { assertMongoUriAllowed } from '../src/mongo-local-vault.js';

describe('MongoDB URI transport policy', () => {
  it.each([
    'mongodb://localhost/kavrix',
    'mongodb://127.0.0.1/kavrix',
    'mongodb://[::1]/kavrix',
    'mongodb://vault.example/kavrix?tls=true',
    'mongodb+srv://vault.example/kavrix?ssl=true',
  ])('accepts a safe target: %s', (uri) => {
    expect(() => assertMongoUriAllowed(uri)).not.toThrow();
  });

  it.each([
    'https://vault.example/kavrix',
    'mongodb://vault.example/kavrix',
    'mongodb://vault.example/kavrix?tls=false',
    'mongodb://vault.example/kavrix?tls=true&tlsAllowInvalidCertificates=true',
    'mongodb://vault.example/kavrix?ssl=true&sslAllowInvalidHostnames=true',
    'mongodb://vault.example/kavrix?ssl=true&sslValidate=false',
  ])('rejects an unsafe or unsupported target: %s', (uri) => {
    expect(() => assertMongoUriAllowed(uri)).toThrow(/database connection failed/iu);
  });
});
