import { z } from 'zod';

import { CLI_ERROR_CODES } from './cli-exit-codes.js';

export {
  CLI_ERROR_CODES,
  CLI_EXIT_CODES,
  cliErrorCodeForRunnerFailure,
  exitCodeForCliError,
  SPAWN_FAILURE_CLI_ERROR_CODE,
} from './cli-exit-codes.js';
export type { CliErrorCode, CliExitCode } from './cli-exit-codes.js';

/** Non-secret destination preflight shared by the interactive UI and CLI host. */
export const profileDestinationCheckActionSchema = z
  .object({
    type: z.literal('validate-profile-destination'),
    path: z.string().min(1).max(4096),
  })
  .strict();

export type ProfileDestinationCheckAction = Readonly<
  z.infer<typeof profileDestinationCheckActionSchema>
>;

export const cliErrorCodeSchema = z.enum(CLI_ERROR_CODES);

export const cliErrorEnvelopeSchema = z
  .object({
    error: z
      .object({
        code: cliErrorCodeSchema,
        exitCode: z.number().int().min(0).max(255),
        message: z.string().min(1).max(1024),
      })
      .strict(),
  })
  .strict();

export type CliErrorEnvelope = z.infer<typeof cliErrorEnvelopeSchema>;
