import { apiBearerTokenSchema, type ApiBearerToken } from '@kavrix/schemas';

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 300_000;
const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
const MAX_CONFIGURED_RESPONSE_BYTES = 256 * 1024 * 1024;
const MAX_RETRY_AFTER_MS = 24 * 60 * 60 * 1_000;

export type SecureFetchOptions = Readonly<{
  baseUrl: string | URL;
  timeoutMs?: number;
  maximumResponseBytes?: number;
  signal?: AbortSignal;
  allowInsecureLoopbackDevelopment?: boolean;
}>;

export type SecureFetchFailureKind =
  | 'protocol'
  | 'timeout'
  | 'aborted'
  | 'offline'
  | 'unauthorized'
  | 'forbidden'
  | 'not-found'
  | 'conflict'
  | 'rate-limited'
  | 'server'
  | 'client';

export class SecureFetchFailure extends Error {
  readonly kind: SecureFetchFailureKind;
  readonly retryAfterMs: number | undefined;

  constructor(kind: SecureFetchFailureKind, retryAfterMs?: number) {
    super('The remote request failed.');
    this.name = 'SecureFetchFailure';
    this.kind = kind;
    this.retryAfterMs = retryAfterMs;
  }
}

type RequestMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';

type RequestOptions = Readonly<{
  method: RequestMethod;
  path: readonly string[];
  expectedStatus: number;
  bearerToken?: ApiBearerToken;
  successorToken?: ApiBearerToken;
  body?: string;
  query?: readonly (readonly [string, string])[];
}>;

type RequestResult = Readonly<{
  response: Response;
  timeoutSignal: AbortSignal;
}>;

export class SecureFetchClient {
  readonly #baseUrl: URL;
  readonly #timeoutMs: number;
  readonly #maximumResponseBytes: number;
  readonly #signal: AbortSignal | undefined;

  constructor(options: SecureFetchOptions) {
    this.#baseUrl = parseBaseUrl(
      options.baseUrl,
      options.allowInsecureLoopbackDevelopment === true,
    );
    this.#timeoutMs = boundedInteger(
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      1,
      MAX_TIMEOUT_MS,
    );
    this.#maximumResponseBytes = boundedInteger(
      options.maximumResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
      1,
      MAX_CONFIGURED_RESPONSE_BYTES,
    );
    this.#signal = options.signal;
  }

  /** Canonical non-secret endpoint used for every request from this client. */
  get baseUrl(): string {
    return this.#baseUrl.href;
  }

  async requestJson(options: RequestOptions): Promise<unknown> {
    const { response, timeoutSignal } = await this.#request(options);
    const contentType = response.headers.get('content-type');
    if (contentType?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') {
      await cancelBody(response);
      throw new SecureFetchFailure('protocol');
    }
    const bytes = await readBoundedBody(
      response,
      this.#maximumResponseBytes,
      // The response body remains subject to the same timeout and caller abort.
      // Fetch rejects the reader when the combined signal aborts.
      { timeoutSignal, externalSignal: this.#signal },
    );
    try {
      const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      return JSON.parse(decoded) as unknown;
    } catch {
      throw new SecureFetchFailure('protocol');
    } finally {
      bytes.fill(0);
    }
  }

  async requestEmpty(options: RequestOptions): Promise<void> {
    const { response } = await this.#request(options);
    const contentLength = response.headers.get('content-length');
    if (contentLength !== null && contentLength !== '0') {
      await cancelBody(response);
      throw new SecureFetchFailure('protocol');
    }
    await cancelBody(response);
  }

  async #request(options: RequestOptions): Promise<RequestResult> {
    const url = this.#url(options.path, options.query);
    const bearerToken = parseToken(options.bearerToken);
    const successorToken = parseToken(options.successorToken);
    const timeoutSignal = AbortSignal.timeout(this.#timeoutMs);
    const signal =
      this.#signal === undefined
        ? timeoutSignal
        : AbortSignal.any([timeoutSignal, this.#signal]);
    let response: Response;
    try {
      response = await fetch(url, {
        method: options.method,
        headers: {
          accept: 'application/json',
          ...(bearerToken === undefined
            ? {}
            : { authorization: `Bearer ${bearerToken}` }),
          ...(successorToken === undefined
            ? {}
            : { 'x-kavrix-successor-token': successorToken }),
          ...(options.body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(options.body === undefined ? {} : { body: options.body }),
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'manual',
        referrerPolicy: 'no-referrer',
        signal,
      });
    } catch {
      throw requestFailure(timeoutSignal, this.#signal);
    }

    if (
      response.redirected ||
      response.type === 'opaqueredirect' ||
      response.url.length === 0 ||
      response.url !== url.href
    ) {
      await cancelBody(response);
      throw new SecureFetchFailure('protocol');
    }
    if (response.status >= 300 && response.status < 400) {
      await cancelBody(response);
      throw new SecureFetchFailure('protocol');
    }
    if (!response.ok) {
      await cancelBody(response);
      throw classifyHttpFailure(response);
    }
    if (response.status !== options.expectedStatus) {
      await cancelBody(response);
      throw new SecureFetchFailure('protocol');
    }
    return { response, timeoutSignal };
  }

  #url(
    path: readonly string[],
    query: readonly (readonly [string, string])[] | undefined,
  ): URL {
    if (path.length === 0 || path.some((segment) => segment.length === 0)) {
      throw new SecureFetchFailure('protocol');
    }
    const encodedPath = path.map((segment) => encodeURIComponent(segment)).join('/');
    const url = new URL(encodedPath, this.#baseUrl);
    if (url.origin !== this.#baseUrl.origin) {
      throw new SecureFetchFailure('protocol');
    }
    for (const entry of query ?? []) {
      url.searchParams.append(entry[0], entry[1]);
    }
    return url;
  }
}

function parseToken(token: ApiBearerToken | undefined): ApiBearerToken | undefined {
  if (token === undefined) return undefined;
  const parsed = apiBearerTokenSchema.safeParse(token);
  if (!parsed.success) throw new SecureFetchFailure('protocol');
  return parsed.data;
}

function parseBaseUrl(value: string | URL, allowInsecureLoopback: boolean): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError('The remote base URL is invalid.');
  }
  if (
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.search.length > 0 ||
    url.hash.length > 0
  ) {
    throw new TypeError(
      'The remote base URL cannot contain credentials or parameters.',
    );
  }
  if (
    url.protocol !== 'https:' &&
    !(
      allowInsecureLoopback &&
      url.protocol === 'http:' &&
      isLoopbackHostname(url.hostname)
    )
  ) {
    throw new TypeError('The remote base URL must use HTTPS.');
  }
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  return new URL(url.href);
}

function isLoopbackHostname(hostname: string): boolean {
  if (hostname === '[::1]') return true;
  const octets = hostname.split('.');
  return (
    octets.length === 4 &&
    octets[0] === '127' &&
    octets.every((octet) => /^\d{1,3}$/u.test(octet) && Number(octet) <= 255)
  );
}

function boundedInteger(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError('A remote request bound is invalid.');
  }
  return value;
}

async function readBoundedBody(
  response: Response,
  maximumBytes: number,
  signals: Readonly<{
    timeoutSignal: AbortSignal;
    externalSignal: AbortSignal | undefined;
  }>,
): Promise<Uint8Array> {
  const contentLength = response.headers.get('content-length');
  if (contentLength !== null) {
    const parsed = Number(contentLength);
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximumBytes) {
      await cancelBody(response);
      throw new SecureFetchFailure('protocol');
    }
  }
  if (response.body === null) throw new SecureFetchFailure('protocol');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      const chunk = next.value as unknown;
      if (!(chunk instanceof Uint8Array)) {
        throw new SecureFetchFailure('protocol');
      }
      total += chunk.byteLength;
      if (total > maximumBytes) throw new SecureFetchFailure('protocol');
      chunks.push(chunk);
    }
    const output = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      output.set(chunk, offset);
      offset += chunk.byteLength;
      chunk.fill(0);
    }
    return output;
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    for (const chunk of chunks) chunk.fill(0);
    if (error instanceof SecureFetchFailure) throw error;
    throw requestFailure(signals.timeoutSignal, signals.externalSignal);
  } finally {
    reader.releaseLock();
  }
}

function requestFailure(
  timeoutSignal: AbortSignal,
  externalSignal: AbortSignal | undefined,
): SecureFetchFailure {
  if (timeoutSignal.aborted) return new SecureFetchFailure('timeout');
  if (externalSignal?.aborted === true) return new SecureFetchFailure('aborted');
  return new SecureFetchFailure('offline');
}

function classifyHttpFailure(response: Response): SecureFetchFailure {
  if (response.status === 401) return new SecureFetchFailure('unauthorized');
  if (response.status === 403) return new SecureFetchFailure('forbidden');
  if (response.status === 404) return new SecureFetchFailure('not-found');
  if (response.status === 408 || response.status === 504) {
    return new SecureFetchFailure('timeout');
  }
  if (response.status === 409) return new SecureFetchFailure('conflict');
  if (response.status === 429) {
    return new SecureFetchFailure(
      'rate-limited',
      parseRetryAfter(response.headers.get('retry-after')),
    );
  }
  if (response.status >= 500) return new SecureFetchFailure('server');
  return new SecureFetchFailure('client');
}

function parseRetryAfter(value: string | null): number | undefined {
  if (value === null) return undefined;
  if (/^\d+$/u.test(value)) {
    const seconds = Number(value);
    return Number.isSafeInteger(seconds)
      ? Math.min(seconds * 1_000, MAX_RETRY_AFTER_MS)
      : undefined;
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return undefined;
  return Math.min(Math.max(0, timestamp - Date.now()), MAX_RETRY_AFTER_MS);
}

async function cancelBody(response: Response): Promise<void> {
  await response.body?.cancel().catch(() => undefined);
}
