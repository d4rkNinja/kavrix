import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export type LoopbackServer = Readonly<{
  url: string;
  close: () => Promise<void>;
}>;

export async function startLoopbackServer(
  handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>,
): Promise<LoopbackServer> {
  const server = createServer((request, response) => {
    Promise.resolve(handler(request, response)).catch(() => {
      response.statusCode = 500;
      response.end();
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${String(address.port)}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined) resolve();
          else reject(error);
        });
        server.closeAllConnections();
      }),
  };
}

export async function readRequest(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const candidate of request as AsyncIterable<unknown>) {
    if (!(candidate instanceof Uint8Array) && typeof candidate !== 'string') {
      throw new TypeError('The request body chunk is invalid.');
    }
    chunks.push(Buffer.from(candidate));
  }
  return Buffer.concat(chunks).toString('utf8');
}
