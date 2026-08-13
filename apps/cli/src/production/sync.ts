import type { CliStatus } from '../contracts.js';
import { runProductionUnlocked, type ProductionUnlockedRequest } from './unlock.js';

export async function executeProductionSync(
  request: ProductionUnlockedRequest,
): Promise<CliStatus> {
  return await runProductionUnlocked(request, async (context) => {
    if (context.ports.sync === undefined) {
      throw new Error('Sync port unavailable during sync');
    }
    return await context.ports.sync();
  });
}
