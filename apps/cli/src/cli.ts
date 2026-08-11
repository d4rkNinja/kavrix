import type { Readable, Writable } from 'node:stream';

import { Command, CommanderError } from 'commander';

import {
  registerCommandCatalog,
  CLI_COMMAND_CATALOG,
  PUBLIC_CLI_COMMAND_CATALOG,
  type CliCommandDescriptor,
  type ProductionStatusCallback,
} from './catalog.js';
import type { CliUseCasePorts } from './contracts.js';
import { CLI_EXIT_CODES, presentCliCommandError } from './errors.js';
import type { CliInitializationDependencies } from './initialization.js';
import { assertSupportedRuntime } from './runtime-preflight.js';
import { NodeSecretInput, type SecretInputPort } from './secret-input.js';
import { sanitizeTerminalOutput, sanitizeTerminalText } from './terminal.js';
import { CLI_VERSION } from './version.js';

export type CliRuntime = Readonly<{
  stdin: Readable;
  stdout: Writable;
  stderr: Writable;
}>;

export type CliDependencies = Readonly<{
  ports: CliUseCasePorts;
  secrets: SecretInputPort;
  initialization?: CliInitializationDependencies;
  runtime: CliRuntime;
}>;

type ProgramDependencies = Readonly<{
  ports?: CliUseCasePorts;
  secrets?: SecretInputPort;
  initialization?: CliInitializationDependencies;
  productionStatus?: ProductionStatusCallback;
  environment?: Readonly<Record<string, string | undefined>>;
  runtime: CliRuntime;
}>;

export function createCliProgram(dependencies: CliDependencies): Command {
  return createProgram(dependencies, CLI_COMMAND_CATALOG);
}

function createProgram(
  dependencies: ProgramDependencies,
  catalog: readonly CliCommandDescriptor[],
): Command {
  const { runtime } = dependencies;
  const program = new Command()
    .name('creds')
    .description('CredVault zero-knowledge credentials vault')
    .version(CLI_VERSION)
    .showSuggestionAfterError(false)
    .allowExcessArguments(false)
    .exitOverride()
    .configureOutput({
      writeOut: (value) => runtime.stdout.write(sanitizeTerminalOutput(value)),
      writeErr: () => undefined,
      outputError: () => undefined,
    });
  program.action(() => {
    program.outputHelp();
  });
  registerCommandCatalog(program, catalog, {
    ...(dependencies.ports === undefined ? {} : { ports: dependencies.ports }),
    ...(dependencies.secrets === undefined ? {} : { secrets: dependencies.secrets }),
    ...(dependencies.initialization === undefined
      ? {}
      : { initialization: dependencies.initialization }),
    ...(dependencies.productionStatus === undefined
      ? {}
      : { productionStatus: dependencies.productionStatus }),
    ...(dependencies.environment === undefined
      ? {}
      : { environment: dependencies.environment }),
    stdout: runtime.stdout,
    stdoutIsTty:
      (runtime.stdout as Writable & Readonly<{ isTTY?: boolean }>).isTTY === true,
  });
  return program;
}

export async function runCli(
  arguments_: readonly string[],
  dependencies: CliDependencies,
): Promise<number> {
  return runProgram(arguments_, dependencies, CLI_COMMAND_CATALOG);
}

export async function runPublicCli(
  arguments_: readonly string[],
  runtime: CliRuntime,
  productionStatus: ProductionStatusCallback = defaultProductionStatus,
): Promise<number> {
  const secrets = new NodeSecretInput(runtime.stdin, runtime.stderr);
  return runProgram(
    arguments_,
    {
      runtime,
      secrets,
      productionStatus,
      environment: process.env,
    },
    PUBLIC_CLI_COMMAND_CATALOG,
  );
}

async function defaultProductionStatus(
  request: Parameters<ProductionStatusCallback>[0],
): ReturnType<ProductionStatusCallback> {
  const { runProductionStatus } = await import('./production/status.js');
  return runProductionStatus(request);
}

async function runProgram(
  arguments_: readonly string[],
  dependencies: ProgramDependencies,
  catalog: readonly CliCommandDescriptor[],
): Promise<number> {
  try {
    // Runs before parsing so an unsupported runtime is reported as itself,
    // rather than surfacing later as a TypeError from a missing primitive.
    assertSupportedRuntime();
    await createProgram(dependencies, catalog).parseAsync([...arguments_], {
      from: 'user',
    });
    return CLI_EXIT_CODES.success;
  } catch (error) {
    if (error instanceof CommanderError) {
      if (
        error.code === 'commander.helpDisplayed' ||
        error.code === 'commander.version'
      ) {
        return CLI_EXIT_CODES.success;
      }
      dependencies.runtime.stderr.write(
        "Error [CLI_USAGE]: Invalid command usage. Run 'creds --help'.\n",
      );
      return CLI_EXIT_CODES.usage;
    }
    const presentation = await presentCliCommandError(error);
    dependencies.runtime.stderr.write(
      `Error [${sanitizeTerminalText(presentation.code)}]: ${sanitizeTerminalText(presentation.message)}\n`,
    );
    return presentation.exitCode;
  }
}

export function productionRuntime(): CliRuntime {
  return { stdin: process.stdin, stdout: process.stdout, stderr: process.stderr };
}
