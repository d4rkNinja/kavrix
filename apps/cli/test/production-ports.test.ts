import { deviceIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { describe, expect, it, vi } from 'vitest';

import { shapeInviteJoinRequest } from '../src/contracts.js';
import {
  createProductionPorts,
  type ProductionPortsOptions,
} from '../src/production/ports.js';

describe('production CLI ports', () => {
  it('forwards the invite server only when explicitly supplied', async () => {
    const request = shapeInviteJoinRequest(
      'A'.repeat(43),
      vaultIdSchema.parse('vault.primary'),
      1,
    );
    const result = {
      vaultId: vaultIdSchema.parse('vault.primary'),
      deviceId: deviceIdSchema.parse('device.new'),
    };
    const join = vi.fn(() => Promise.resolve(result));
    const options: ProductionPortsOptions = {
      profile: {} as never,
      environment: {} as never,
      secrets: {} as never,
      join,
    };
    const ports = createProductionPorts(options);

    await ports.joinInvite(request, 'portable-key');
    await ports.joinInvite(request, 'portable-key', 'https://sync.example/');

    expect(join).toHaveBeenNthCalledWith(1, request, 'portable-key');
    expect(join).toHaveBeenNthCalledWith(
      2,
      request,
      'portable-key',
      'https://sync.example/',
    );
  });
});
