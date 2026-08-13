import type {
  CliConflict,
  CliConflictResolutionRequest,
  CliConflictResolutionResult,
} from '../contracts.js';
import { runProductionUnlocked, type ProductionUnlockedRequest } from './unlock.js';

export async function executeProductionConflictList(
  request: ProductionUnlockedRequest,
): Promise<readonly CliConflict[]> {
  return runProductionUnlocked(request, async (context) => {
    if (context.ports.listConflicts === undefined) {
      throw new Error('Conflict listing is unavailable during unlocked runner');
    }
    return context.ports.listConflicts();
  });
}

export async function executeProductionConflictResolution(
  request: ProductionUnlockedRequest,
  conflict: CliConflictResolutionRequest,
): Promise<CliConflictResolutionResult> {
  return runProductionUnlocked(request, async (context) => {
    if (context.ports.resolveConflict === undefined) {
      throw new Error('Conflict resolution is unavailable during unlocked runner');
    }
    return context.ports.resolveConflict(conflict);
  });
}
