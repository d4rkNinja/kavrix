import {
  ApiServiceConfigurationError,
  parseMongoApiServiceEnvironment,
} from './service-environment.js';
import { startMongoApiServer, type MongoApiServerConfig } from './server.js';

export const apiServiceExitCode = {
  success: 0,
  runtimeFailure: 1,
  invalidConfiguration: 78,
} as const;

type ShutdownSignal = 'SIGINT' | 'SIGTERM';

interface RunningApiServer {
  readonly address: string;
  close(): Promise<void>;
}

interface SignalSource {
  on(signal: ShutdownSignal, listener: () => void): unknown;
  off(signal: ShutdownSignal, listener: () => void): unknown;
}

interface ServiceOutput {
  write(message: string): unknown;
}

export interface MongoApiServiceRuntime {
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly signals: SignalSource;
  readonly output: ServiceOutput;
  readonly startServer: (config: MongoApiServerConfig) => Promise<RunningApiServer>;
}

const defaultRuntime: MongoApiServiceRuntime = {
  environment: process.env,
  signals: process,
  output: process.stderr,
  startServer: startMongoApiServer,
};

/** Runs until SIGINT/SIGTERM and returns a stable process exit code. */
export async function runMongoApiService(
  runtime: MongoApiServiceRuntime = defaultRuntime,
): Promise<number> {
  let serviceConfig;
  try {
    serviceConfig = parseMongoApiServiceEnvironment(runtime.environment);
  } catch (error) {
    const setting =
      error instanceof ApiServiceConfigurationError ? ` (${error.setting})` : '';
    runtime.output.write(`[kavrix-api] configuration invalid${setting}\n`);
    return apiServiceExitCode.invalidConfiguration;
  }

  const shutdown = Promise.withResolvers<ShutdownSignal>();
  const onInterrupt = (): void => {
    shutdown.resolve('SIGINT');
  };
  const onTerminate = (): void => {
    shutdown.resolve('SIGTERM');
  };
  const removeSignalHandlers = (): void => {
    runtime.signals.off('SIGINT', onInterrupt);
    runtime.signals.off('SIGTERM', onTerminate);
  };
  runtime.signals.on('SIGINT', onInterrupt);
  runtime.signals.on('SIGTERM', onTerminate);

  const startup = runtime.startServer(serviceConfig.server).then(
    (server) => ({ status: 'started', server }) as const,
    () => ({ status: 'failed' }) as const,
  );
  const first = await Promise.race([
    startup,
    shutdown.promise.then(() => ({ status: 'shutdown-requested' }) as const),
  ]);

  let server: RunningApiServer;
  if (first.status === 'failed') {
    removeSignalHandlers();
    runtime.output.write('[kavrix-api] startup failed\n');
    return apiServiceExitCode.runtimeFailure;
  }
  if (first.status === 'shutdown-requested') {
    const eventualStartup = await startup;
    if (eventualStartup.status === 'failed') {
      removeSignalHandlers();
      runtime.output.write('[kavrix-api] startup failed\n');
      return apiServiceExitCode.runtimeFailure;
    }
    server = eventualStartup.server;
  } else {
    server = first.server;
    runtime.output.write('[kavrix-api] started\n');
    await shutdown.promise;
  }

  removeSignalHandlers();
  runtime.output.write('[kavrix-api] shutdown requested\n');
  const result = await closeWithin(server, serviceConfig.shutdownTimeoutMs);
  if (result === 'closed') {
    runtime.output.write('[kavrix-api] stopped\n');
    return apiServiceExitCode.success;
  }
  runtime.output.write(
    result === 'timed-out'
      ? '[kavrix-api] shutdown timed out\n'
      : '[kavrix-api] shutdown failed\n',
  );
  return apiServiceExitCode.runtimeFailure;
}

async function closeWithin(
  server: RunningApiServer,
  timeoutMs: number,
): Promise<'closed' | 'failed' | 'timed-out'> {
  return new Promise((resolve) => {
    let completed = false;
    const timer = setTimeout(() => {
      if (completed) return;
      completed = true;
      resolve('timed-out');
    }, timeoutMs);
    void server.close().then(
      () => {
        if (completed) return;
        completed = true;
        clearTimeout(timer);
        resolve('closed');
      },
      () => {
        if (completed) return;
        completed = true;
        clearTimeout(timer);
        resolve('failed');
      },
    );
  });
}
